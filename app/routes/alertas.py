import json

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import feedback, incidentes, resposta
from app.config import settings
from app.database import get_db
from app.enriquecimento import get_http_client, obter_reputacao
from app.ia import ErroIA, LimiteIA, analisar_alerta, para_saida, ultima_analise
from app.models import Alerta, Analise, Bloqueio, agora_utc
from app.politicas import ip_malicioso
from app.schemas import (
    AlertaSaida,
    AlertaWazuh,
    AnaliseIA,
    AnaliseSaida,
    BloqueioSaida,
    ReputacaoSaida,
    ResumoAnalise,
    ResumoIncidente,
    RevisaoEntrada,
)
from app.security import verificar_token

# Todas as rotas exigem token: a listagem expõe dados de segurança.
router = APIRouter(
    prefix="/api/alertas", tags=["alertas"], dependencies=[Depends(verificar_token)]
)


def _buscar_alerta(db: Session, alerta_id: int) -> Alerta:
    alerta = db.get(Alerta, alerta_id)
    if alerta is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alerta não encontrado")
    return alerta


@router.post("", response_model=AlertaSaida, status_code=status.HTTP_201_CREATED)
def receber_alerta(alerta: AlertaWazuh, response: Response, db: Session = Depends(get_db)):
    existente = db.scalar(select(Alerta).where(Alerta.wazuh_id == alerta.id))
    if existente is not None:
        # Reenvio do mesmo alerta: idempotente, devolve o registro que já existe.
        response.status_code = status.HTTP_200_OK
        return existente

    novo = Alerta(
        wazuh_id=alerta.id,
        rule_id=alerta.rule.id,
        rule_level=alerta.rule.level,
        rule_description=alerta.rule.description,
        agent_name=alerta.agent.name if alerta.agent else None,
        srcip=alerta.srcip(),
        full_log=alerta.full_log,
        # exclude_unset: grava o que chegou, sem os None dos campos opcionais ausentes.
        raw_json=json.dumps(
            alerta.model_dump(mode="json", exclude_unset=True), ensure_ascii=False
        ),
    )
    db.add(novo)
    try:
        db.commit()
    except IntegrityError:
        # Dois envios simultâneos: o índice único barrou o segundo.
        db.rollback()
        response.status_code = status.HTTP_200_OK
        return db.scalar(select(Alerta).where(Alerta.wazuh_id == alerta.id))
    db.refresh(novo)
    incidentes.agrupar(db, novo)
    db.commit()
    return novo


@router.get("", response_model=list[AlertaSaida])
def listar_alertas(limite: int = Query(100, ge=1, le=500), db: Session = Depends(get_db)):
    consulta = (
        select(Alerta).order_by(Alerta.recebido_em.desc(), Alerta.id.desc()).limit(limite)
    )
    alertas = db.scalars(consulta).all()
    ultimas: dict[int, Analise] = {}
    if alertas:
        analises = db.scalars(
            select(Analise)
            .where(Analise.alerta_id.in_([a.id for a in alertas]))
            .order_by(Analise.criada_em, Analise.id)
        )
        for analise in analises:
            ultimas[analise.alerta_id] = analise  # a mais recente sobrescreve as anteriores
    por_alerta = incidentes.resumos_por_alerta(db, [a.id for a in alertas])
    return [_saida_com_resumo(a, ultimas.get(a.id), por_alerta.get(a.id)) for a in alertas]


def _saida_com_resumo(
    alerta: Alerta, analise: Analise | None, incidente: ResumoIncidente | None
) -> AlertaSaida:
    saida = AlertaSaida.model_validate(alerta)
    saida.incidente = incidente
    if analise is None:
        return saida
    sugestao = AnaliseIA.model_validate_json(analise.sugestao_json)
    saida.analise = ResumoAnalise(
        id=analise.id,
        revisao=analise.revisao,
        classificacao=sugestao.classificacao,
        severidade=sugestao.severidade,
        acao_sugerida=sugestao.acao_sugerida,
        indicios_manipulacao=sugestao.indicios_manipulacao,
    )
    return saida


@router.get("/{alerta_id}/reputacao", response_model=ReputacaoSaida)
def reputacao_do_alerta(
    alerta_id: int,
    db: Session = Depends(get_db),
    cliente: httpx.Client = Depends(get_http_client),
):
    alerta = _buscar_alerta(db, alerta_id)
    return obter_reputacao(db, cliente, alerta.srcip)


@router.post(
    "/{alerta_id}/analise", response_model=AnaliseSaida, status_code=status.HTTP_201_CREATED
)
def pedir_analise(
    alerta_id: int,
    response: Response,
    refazer: bool = False,
    db: Session = Depends(get_db),
    cliente: httpx.Client = Depends(get_http_client),
):
    alerta = _buscar_alerta(db, alerta_id)
    existente = None if refazer else ultima_analise(db, alerta_id)
    if existente is not None:
        # Cada análise gasta cota da IA: reaproveita a última, a não ser que peçam outra.
        response.status_code = status.HTTP_200_OK
        return para_saida(existente)
    if settings.gemini_api_key is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="IA não configurada (GEMINI_API_KEY no .env)",
        )

    incidente = incidentes.do_alerta(db, alerta_id)
    if refazer and incidente is not None and incidente.decisao is not None:
        # Pedir outra análise reabre o incidente: ele volta para a fila.
        incidente.decisao = None
        incidente.decidido_em = None
        db.commit()
    reputacao = obter_reputacao(db, cliente, alerta.srcip)
    try:
        registro = analisar_alerta(db, cliente, alerta, reputacao, incidentes.contexto(db, alerta_id))
    except LimiteIA:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Limite de uso da IA atingido; tente mais tarde",
        )
    except ErroIA as erro:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Falha na análise por IA: {erro}"
        )
    return para_saida(registro)


@router.get("/{alerta_id}/analise", response_model=AnaliseSaida)
def consultar_analise(alerta_id: int, db: Session = Depends(get_db)):
    _buscar_alerta(db, alerta_id)
    registro = ultima_analise(db, alerta_id)
    if registro is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alerta ainda sem análise")
    return para_saida(registro)


@router.post("/{alerta_id}/revisao", response_model=AnaliseSaida)
def revisar_analise(
    alerta_id: int,
    revisao: RevisaoEntrada,
    db: Session = Depends(get_db),
    cliente: httpx.Client = Depends(get_http_client),
):
    """A decisão do analista. É a única coisa que muda a revisão de uma análise."""
    alerta = _buscar_alerta(db, alerta_id)
    registro = ultima_analise(db, alerta_id)
    if registro is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Analise o alerta antes de revisar")
    if registro.revisao != "pendente":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Esta análise já foi revisada")

    sugestao = AnaliseIA.model_validate_json(registro.sugestao_json)
    if revisao.correcao is not None and revisao.correcao == feedback.decisao_final(
        sugestao, RevisaoEntrada(decisao="aprovada")
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="A correção não muda nada na sugestão; use Aprovar",
        )

    registro.revisao = revisao.decisao
    registro.revisado_em = agora_utc()
    incidente = incidentes.do_alerta(db, alerta_id)
    if incidente is not None:
        # A decisão vale para todos os alertas do incidente.
        incidente.decisao = revisao.decisao
        incidente.decidido_em = registro.revisado_em
    registro.correcao_json = json.dumps(
        {
            "correcao": revisao.correcao.model_dump() if revisao.correcao else None,
            "nota": revisao.nota,
        },
        ensure_ascii=False,
    )
    db.commit()
    db.refresh(registro)

    # Reputação vem do cache na maioria das vezes: a análise acabou de consultá-la.
    reputacao = obter_reputacao(db, cliente, alerta.srcip)
    dados_reputacao = {n: r.dados for n, r in reputacao.fontes.items() if r.status == "ok"}
    feedback.registrar(
        alerta_id=alerta.id,
        analise_id=registro.id,
        regra={"id": alerta.rule_id, "nivel": alerta.rule_level, "descricao": alerta.rule_description},
        sugestao=sugestao,
        revisao=revisao,
        suspeito=sugestao.indicios_manipulacao or ip_malicioso(dados_reputacao),
    )
    return para_saida(registro)


def _acao_final(registro: Analise) -> str:
    """A ação que o analista aprovou: a corrigida, se corrigiu; senão, a sugestão final."""
    if registro.correcao_json:
        correcao = json.loads(registro.correcao_json).get("correcao")
        if correcao:
            return correcao["acao_sugerida"]
    return AnaliseIA.model_validate_json(registro.sugestao_json).acao_sugerida


@router.post("/{alerta_id}/bloqueio", response_model=BloqueioSaida, status_code=status.HTTP_201_CREATED)
def bloquear_ip(
    alerta_id: int,
    response: Response,
    db: Session = Depends(get_db),
    cliente: httpx.Client = Depends(resposta.get_cliente_wazuh),
):
    """Executa o firewall-drop no agente. Exige a decisão do analista de bloquear o IP."""
    alerta = _buscar_alerta(db, alerta_id)
    registro = ultima_analise(db, alerta_id)
    if registro is None or registro.revisao not in ("aprovada", "corrigida") or _acao_final(registro) != "bloquear_ip":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="O bloqueio exige a decisão do analista de bloquear o IP (aprovada ou corrigida)",
        )
    if not alerta.srcip:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Alerta sem IP de origem")
    agente_id = (json.loads(alerta.raw_json).get("agent") or {}).get("id")
    if not agente_id or agente_id == "000":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Alerta do próprio manager: não há agente onde aplicar o bloqueio",
        )
    if resposta.protegido(alerta.srcip):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="IP protegido: nunca é bloqueado")
    if not resposta.configurado():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API do Wazuh não configurada (WAZUH_API_URL no .env)",
        )

    anterior = db.scalar(
        select(Bloqueio).where(Bloqueio.ip == alerta.srcip, Bloqueio.agente_id == agente_id, Bloqueio.sucesso.is_(True))
    )
    if anterior is not None:
        # Já bloqueado neste agente: não reenviar o comando.
        response.status_code = status.HTTP_200_OK
        return anterior

    try:
        detalhe, sucesso = resposta.bloquear(cliente, alerta.srcip, agente_id), True
    except resposta.ErroBloqueio as erro:
        detalhe, sucesso = str(erro), False
    bloqueio = Bloqueio(alerta_id=alerta.id, ip=alerta.srcip, agente_id=agente_id, sucesso=sucesso, detalhe=detalhe)
    db.add(bloqueio)
    db.commit()
    db.refresh(bloqueio)
    if not sucesso:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Bloqueio falhou: {detalhe}")
    return bloqueio


@router.get("/{alerta_id}/bloqueio", response_model=BloqueioSaida)
def consultar_bloqueio(alerta_id: int, db: Session = Depends(get_db)):
    alerta = _buscar_alerta(db, alerta_id)
    agente_id = (json.loads(alerta.raw_json).get("agent") or {}).get("id")
    bloqueio = db.scalar(
        select(Bloqueio)
        .where(Bloqueio.ip == alerta.srcip, Bloqueio.agente_id == agente_id, Bloqueio.sucesso.is_(True))
        .order_by(Bloqueio.executado_em.desc())
        .limit(1)
    )
    if bloqueio is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IP não bloqueado neste agente")
    return bloqueio
