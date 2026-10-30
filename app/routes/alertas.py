import json

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import feedback
from app.config import settings
from app.database import get_db
from app.enriquecimento import get_http_client, obter_reputacao
from app.ia import ErroIA, LimiteIA, analisar_alerta, para_saida, ultima_analise
from app.models import Alerta, Analise, agora_utc
from app.politicas import ip_malicioso
from app.schemas import (
    AlertaSaida,
    AlertaWazuh,
    AnaliseIA,
    AnaliseSaida,
    ReputacaoSaida,
    ResumoAnalise,
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
    return [_saida_com_resumo(alerta, ultimas.get(alerta.id)) for alerta in alertas]


def _saida_com_resumo(alerta: Alerta, analise: Analise | None) -> AlertaSaida:
    saida = AlertaSaida.model_validate(alerta)
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

    reputacao = obter_reputacao(db, cliente, alerta.srcip)
    try:
        registro = analisar_alerta(db, cliente, alerta, reputacao)
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
