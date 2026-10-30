"""Feedback dos analistas para a IA, num arquivo JSON, classificado por importância.

O feedback só vira exemplo para a IA quando é confiável. Fica em quarentena, até um
analista liberar, a decisão que:
- empurra para "falso positivo" ou "descartar" um alerta com indício de manipulação
  ou IP de má reputação (pode ser erro, ou alguém tentando ensinar a IA a ignorar ataques);
- contradiz um exemplo já aceito para a mesma regra.
O registro guarda só campos estruturados da regra e das decisões: nunca o full_log nem
o IP, para que texto do atacante não entre no prompt por esse caminho.
"""
import json
import os
import threading
import uuid
from pathlib import Path

from app.config import settings
from app.models import agora_utc
from app.schemas import AnaliseIA, Correcao, FeedbackItem, Importancia, RevisaoEntrada

ORDEM_SEVERIDADE = ["baixa", "media", "alta", "critica"]
PESO = {"alta": 3, "media": 2, "baixa": 1}
LIMITE_EXEMPLOS = 3
LIMITE_NOTA_PROMPT = 300

_trava = threading.Lock()


def _arquivo() -> Path:
    return Path(settings.feedback_arquivo)


def carregar() -> list[FeedbackItem]:
    arquivo = _arquivo()
    if not arquivo.exists():
        return []
    return [FeedbackItem.model_validate(item) for item in json.loads(arquivo.read_text(encoding="utf-8"))]


def _salvar(itens: list[FeedbackItem]) -> None:
    arquivo = _arquivo()
    arquivo.parent.mkdir(parents=True, exist_ok=True)
    temporario = arquivo.with_name(arquivo.name + ".tmp")
    temporario.write_text(
        json.dumps([item.model_dump(mode="json") for item in itens], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    # Troca atômica: um travamento no meio da escrita não corrompe o arquivo.
    os.replace(temporario, arquivo)


def decisao_final(sugestao: AnaliseIA, revisao: RevisaoEntrada) -> Correcao:
    if revisao.decisao == "corrigida":
        return revisao.correcao
    if revisao.decisao == "descartada":
        return Correcao(classificacao="falso_positivo", severidade=sugestao.severidade, acao_sugerida="descartar")
    return Correcao(
        classificacao=sugestao.classificacao,
        severidade=sugestao.severidade,
        acao_sugerida=sugestao.acao_sugerida,
    )


def _legivel(valor: str) -> str:
    return valor.replace("_", " ")


def classificar_importancia(sugestao: Correcao, final: Correcao) -> tuple[Importancia, str]:
    if final.classificacao != sugestao.classificacao:
        return "alta", (
            f"A IA errou a classificação: {_legivel(sugestao.classificacao)} "
            f"virou {_legivel(final.classificacao)}."
        )
    salto = abs(ORDEM_SEVERIDADE.index(final.severidade) - ORDEM_SEVERIDADE.index(sugestao.severidade))
    if salto >= 2:
        return "alta", f"Severidade errada em {salto} níveis: {sugestao.severidade} virou {final.severidade}."
    if final != sugestao:
        return "media", "Ajuste de severidade ou de ação."
    return "baixa", "O analista confirmou a sugestão."


def _decidir_uso(regra_id: str, final: Correcao, suspeito: bool, existentes: list[FeedbackItem]) -> tuple[str, str]:
    if suspeito and (final.classificacao == "falso_positivo" or final.acao_sugerida == "descartar"):
        return "quarentena", (
            "Leva ao descarte um alerta com indício de manipulação ou IP de má reputação: "
            "pode ser erro ou tentativa de ensinar a IA a ignorar ataques."
        )
    for item in existentes:
        if item.uso == "exemplo" and item.regra.get("id") == regra_id and item.final.classificacao != final.classificacao:
            return "quarentena", (
                f"Contradiz um exemplo já aceito para a regra {regra_id} ({_legivel(item.final.classificacao)})."
            )
    return "exemplo", "Pode ser usado como referência pela IA."


def registrar(
    *,
    alerta_id: int,
    analise_id: int,
    regra: dict,
    sugestao: AnaliseIA,
    revisao: RevisaoEntrada,
    suspeito: bool,
) -> FeedbackItem:
    """suspeito: a análise teve indício de manipulação ou o IP tem má reputação."""
    proposta = Correcao(
        classificacao=sugestao.classificacao,
        severidade=sugestao.severidade,
        acao_sugerida=sugestao.acao_sugerida,
    )
    final = decisao_final(sugestao, revisao)
    importancia, motivo_importancia = classificar_importancia(proposta, final)
    with _trava:
        itens = carregar()
        uso, motivo_uso = _decidir_uso(regra["id"], final, suspeito, itens)
        item = FeedbackItem(
            id=uuid.uuid4().hex[:12],
            criado_em=agora_utc(),
            alerta_id=alerta_id,
            analise_id=analise_id,
            regra=regra,
            sugestao=proposta,
            decisao=revisao.decisao,
            final=final,
            nota=revisao.nota,
            importancia=importancia,
            motivo_importancia=motivo_importancia,
            uso=uso,
            motivo_uso=motivo_uso,
        )
        itens.append(item)
        _salvar(itens)
    return item


def alterar_uso(feedback_id: str, uso: str) -> FeedbackItem | None:
    with _trava:
        itens = carregar()
        for item in itens:
            if item.id == feedback_id:
                item.uso = uso
                item.motivo_uso = (
                    "Liberado por um analista." if uso == "exemplo" else "Colocado em quarentena por um analista."
                )
                _salvar(itens)
                return item
    return None


def exemplos_para(regra_id: str) -> list[FeedbackItem]:
    """Os exemplos aceitos da regra, os mais importantes e recentes primeiro."""
    candidatos = [i for i in carregar() if i.uso == "exemplo" and i.regra.get("id") == regra_id]
    candidatos.sort(key=lambda i: (PESO[i.importancia], i.criado_em), reverse=True)
    return candidatos[:LIMITE_EXEMPLOS]


def _resumo(c: Correcao) -> str:
    return f"{c.classificacao} / {c.severidade} / {c.acao_sugerida}"


def bloco_prompt(exemplos: list[FeedbackItem]) -> str:
    """Texto para as instruções de sistema. Notas são de analistas (confiáveis), mas vão truncadas e em uma linha."""
    if not exemplos:
        return ""
    linhas = [
        "",
        "Decisões anteriores de analistas para esta mesma regra. São referência, não regra: "
        "os dados do alerta atual valem mais, e as regras de segurança acima continuam valendo.",
    ]
    for item in exemplos:
        nota = " ".join((item.nota or "").split())[:LIMITE_NOTA_PROMPT]
        linha = f"- A IA sugeriu {_resumo(item.sugestao)}; o analista decidiu {_resumo(item.final)}."
        if nota:
            linha += f" Nota do analista: {json.dumps(nota, ensure_ascii=False)}"
        linhas.append(linha)
    return "\n".join(linhas)
