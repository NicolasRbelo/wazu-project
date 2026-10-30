"""Regras fixas aplicadas depois da IA: quem decide os limites é o código, não o modelo.

Quem injeta instruções num log quase sempre quer que o alerta seja descartado.
Por isso, com indício de manipulação ou IP de má reputação, a sugestão nunca
fica como falso positivo nem como descartar.
"""
import re
from collections.abc import Iterator
from typing import Any
from urllib.parse import unquote_plus

from app.schemas import AnaliseIA

SCORE_ABUSEIPDB_MALICIOSO = 75
MOTORES_VT_MALICIOSO = 3

PADROES_INJECAO = [
    re.compile(padrao, re.IGNORECASE)
    for padrao in (
        r"ignor\w*\s+(?:\w+\s+){0,3}instru",  # "ignore as instruções", "ignore all previous instructions"
        r"desconsider\w*\s+(?:\w+\s+){0,3}instru",
        r"system\s*prompt|prompt\s+do\s+sistema",
        r"you\s+are\s+now|voc[eê]\s+agora\s+[eé]",
        r"(?:false|falso)\s+positiv",
        r"<\s*/?\s*(?:system|assistant|dados\s+nao\s+confiaveis)",
        # Campos do formato de resposta da IA no meio de um log: alguém tentando ditar a saída.
        r"classificacao|acao\s+sugerida|indicios\s+manipulacao",
        # Alegação de autorização endereçada a quem faz a triagem.
        r"(?:n[aã]o|do\s+not|don'?t)\s+escal",
        r"(?:pentest|red\s*team)\s+(?:\w+\s+){0,2}autoriz|authori[sz]ed\s+(?:pentest|red\s*team|test|scan)",
        r"autorizad\w*\s+pel[oa]\s",
    )
]


def _normalizar(texto: str) -> str:
    # Decodifica a URL (%20, +) e troca _ e - por espaço: "falso_positivo", "teste-autorizado".
    return re.sub(r"[_\-]+", " ", unquote_plus(texto))


def _textos(valor: Any) -> Iterator[str]:
    if isinstance(valor, str):
        yield valor
    elif isinstance(valor, dict):
        for item in valor.values():
            yield from _textos(item)
    elif isinstance(valor, list):
        for item in valor:
            yield from _textos(item)


def detectar_injecao(contexto: dict) -> bool:
    # Só o que pode vir do atacante: o log, os campos decodificados e os textos das fontes.
    alvos = [
        contexto.get("log_original"),
        contexto.get("campos_decodificados"),
        contexto.get("reputacao_ip"),
    ]
    textos = [_normalizar(texto) for texto in _textos(alvos)]
    return any(padrao.search(texto) for texto in textos for padrao in PADROES_INJECAO)


def ip_malicioso(reputacao: dict) -> bool:
    abuse = reputacao.get("abuseipdb") or {}
    vt = reputacao.get("virustotal") or {}
    denunciado = abuse.get("score", 0) >= SCORE_ABUSEIPDB_MALICIOSO and not abuse.get("na_whitelist")
    return denunciado or vt.get("maliciosos", 0) >= MOTORES_VT_MALICIOSO


def aplicar_politicas(sugestao: AnaliseIA, contexto: dict) -> tuple[AnaliseIA, list[str]]:
    """Devolve a sugestão final e a lista do que foi mudado, em linguagem de analista."""
    final = sugestao.model_copy(deep=True)
    ajustes: list[str] = []

    if not final.indicios_manipulacao and detectar_injecao(contexto):
        final.indicios_manipulacao = True
        ajustes.append(
            "Os dados do alerta têm texto com cara de instrução para a IA "
            "(possível prompt injection), e a IA não marcou isso."
        )

    motivos = []
    if final.indicios_manipulacao:
        motivos.append("indícios de manipulação da IA")
    if ip_malicioso(contexto.get("reputacao_ip") or {}):
        motivos.append("IP de origem com má reputação")
    if not motivos:
        return final, ajustes
    porque = " e ".join(motivos)

    if final.classificacao == "falso_positivo":
        ajustes.append(f"Classificação trocada de 'falso_positivo' para 'inconclusivo': {porque}.")
        final.classificacao = "inconclusivo"
    if final.acao_sugerida == "descartar":
        ajustes.append(f"Ação trocada de 'descartar' para 'investigar': {porque}.")
        final.acao_sugerida = "investigar"
    if final.indicios_manipulacao and final.severidade == "baixa":
        ajustes.append("Severidade elevada de 'baixa' para 'media': alerta com indícios de manipulação.")
        final.severidade = "media"
    return final, ajustes
