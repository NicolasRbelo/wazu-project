import ipaddress
import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class RegraWazuh(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str = Field(min_length=1, max_length=16)
    level: int = Field(ge=0, le=15)
    description: str
    groups: list[str] = []


class AgenteWazuh(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str | None = None
    name: str | None = None
    ip: str | None = None


class AlertaWazuh(BaseModel):
    """Alerta como o Wazuh envia. Campos desconhecidos são aceitos e vão para raw_json."""

    model_config = ConfigDict(extra="allow")

    id: str = Field(min_length=1, max_length=64)
    rule: RegraWazuh
    agent: AgenteWazuh | None = None
    # O conteúdo de "data" depende do decoder e é extraído do log: não confiável.
    data: dict[str, Any] | None = None
    full_log: str | None = None

    def srcip(self) -> str | None:
        """IP de origem normalizado, ou None se ausente ou inválido (o valor bruto fica em raw_json)."""
        valor = (self.data or {}).get("srcip")
        if not isinstance(valor, str):
            return None
        try:
            return str(ipaddress.ip_address(valor))
        except ValueError:
            return None


class AlertaSaida(BaseModel):
    """Alerta como a API devolve. raw_json fica de fora de propósito."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    wazuh_id: str
    rule_id: str
    rule_level: int
    rule_description: str
    agent_name: str | None
    srcip: str | None
    full_log: str | None
    recebido_em: datetime
    # Só na listagem: o resumo da última análise, para a fila saber o que está pendente.
    analise: "ResumoAnalise | None" = None
    incidente: "ResumoIncidente | None" = None


class ReputacaoAbuseIPDB(BaseModel):
    """Campos aproveitados de "data" em /api/v2/check. O resto da resposta é descartado."""

    score: int = Field(validation_alias="abuseConfidenceScore", ge=0, le=100)
    total_denuncias: int = Field(validation_alias="totalReports", ge=0)
    pais: str | None = Field(None, validation_alias="countryCode")
    isp: str | None = None
    dominio: str | None = Field(None, validation_alias="domain")
    tipo_uso: str | None = Field(None, validation_alias="usageType")
    ultima_denuncia: datetime | None = Field(None, validation_alias="lastReportedAt")
    na_whitelist: bool | None = Field(None, validation_alias="isWhitelisted")
    tor: bool | None = Field(None, validation_alias="isTor")


class ReputacaoVirusTotal(BaseModel):
    """Campos aproveitados de "data.attributes" em /api/v3/ip_addresses/{ip}."""

    maliciosos: int = Field(ge=0)
    suspeitos: int = Field(ge=0)
    inofensivos: int = Field(ge=0)
    nao_detectados: int = Field(ge=0)
    reputacao: int | None = None
    pais: str | None = None
    dono_as: str | None = None
    rede: str | None = None


class ResultadoFonte(BaseModel):
    status: Literal["ok", "nao_configurado", "limite_excedido", "erro"]
    em_cache: bool = False
    consultado_em: datetime | None = None
    dados: dict[str, Any] | None = None
    erro: str | None = None


class ReputacaoSaida(BaseModel):
    """Reputação do srcip de um alerta.

    Textos vindos das fontes (isp, dominio, dono_as...) são controlados por terceiros
    e às vezes pelo próprio atacante: tão não confiáveis quanto o full_log.
    """

    ip: str | None
    publico: bool
    fontes: dict[str, ResultadoFonte]


Classificacao = Literal["verdadeiro_positivo", "falso_positivo", "inconclusivo"]
Severidade = Literal["baixa", "media", "alta", "critica"]
Acao = Literal["bloquear_ip", "investigar", "monitorar", "descartar"]
Revisao = Literal["pendente", "aprovada", "corrigida", "descartada"]
Decisao = Literal["aprovada", "corrigida", "descartada"]

MITRE_ID = re.compile(r"T\d{4}(?:\.\d{3})?")
LIMITE_TEXTO_IA = 1000


class AnaliseIA(BaseModel):
    """Formato exigido da IA. Validado aqui também: a saída do modelo não é confiável."""

    classificacao: Classificacao
    severidade: Severidade
    confianca: int = Field(ge=0, le=100)
    acao_sugerida: Acao
    resumo: str
    justificativa: str
    tecnicas_mitre: list[str] = []
    indicios_manipulacao: bool

    @field_validator("resumo", "justificativa")
    @classmethod
    def _limitar_texto(cls, texto: str) -> str:
        return texto.strip()[:LIMITE_TEXTO_IA]

    @field_validator("tecnicas_mitre")
    @classmethod
    def _so_ids_mitre(cls, ids: list[str]) -> list[str]:
        return [i for i in dict.fromkeys(ids) if MITRE_ID.fullmatch(i)][:10]


class ResumoAnalise(BaseModel):
    id: int
    revisao: Revisao
    classificacao: Classificacao
    severidade: Severidade
    acao_sugerida: Acao
    indicios_manipulacao: bool


class ResumoIncidente(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    total: int
    nivel_max: int
    primeiro_em: datetime
    ultimo_em: datetime
    decisao: Decisao | None


AlertaSaida.model_rebuild()


class Correcao(BaseModel):
    classificacao: Classificacao
    severidade: Severidade
    acao_sugerida: Acao


MINIMO_NOTA = 10


class RevisaoEntrada(BaseModel):
    """Decisão do analista sobre a última análise de um alerta."""

    decisao: Decisao
    correcao: Correcao | None = None
    nota: str | None = Field(None, max_length=1000)

    @model_validator(mode="after")
    def _coerente(self) -> "RevisaoEntrada":
        nota = (self.nota or "").strip()
        if self.decisao == "corrigida" and self.correcao is None:
            raise ValueError("Corrigir exige os campos corrigidos.")
        if self.decisao != "corrigida" and self.correcao is not None:
            raise ValueError("Só a decisão 'corrigida' leva correção.")
        if self.decisao in ("corrigida", "descartada") and len(nota) < MINIMO_NOTA:
            raise ValueError(f"Explique a decisão na nota (mínimo de {MINIMO_NOTA} caracteres).")
        self.nota = nota or None
        return self


class AnaliseSaida(BaseModel):
    id: int
    alerta_id: int
    modelo: str
    sugestao: AnaliseIA
    sugestao_ia: AnaliseIA
    ajustes: list[str]
    revisao: Revisao
    criada_em: datetime
    revisado_em: datetime | None = None
    correcao: Correcao | None = None
    nota: str | None = None


Importancia = Literal["alta", "media", "baixa"]
UsoFeedback = Literal["exemplo", "quarentena"]


class FeedbackItem(BaseModel):
    """Uma decisão de analista guardada para a IA. Nunca leva full_log nem IP."""

    id: str
    criado_em: datetime
    alerta_id: int
    analise_id: int
    regra: dict[str, Any]
    sugestao: Correcao
    decisao: Decisao
    final: Correcao
    nota: str | None
    importancia: Importancia
    motivo_importancia: str
    uso: UsoFeedback
    motivo_uso: str


class UsoEntrada(BaseModel):
    uso: UsoFeedback


class BloqueioSaida(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alerta_id: int
    ip: str
    agente_id: str
    sucesso: bool
    detalhe: str
    executado_em: datetime
