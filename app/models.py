from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def agora_utc() -> datetime:
    return datetime.now(timezone.utc)


class Alerta(Base):
    __tablename__ = "alertas"

    id: Mapped[int] = mapped_column(primary_key=True)

    # unique: segunda barreira contra duplicata, caso dois envios cheguem juntos.
    wazuh_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    rule_id: Mapped[str] = mapped_column(String(16))
    rule_level: Mapped[int] = mapped_column(Integer)
    # Text: descrições de regra podem interpolar campos do log, ex. $(srcip).
    rule_description: Mapped[str] = mapped_column(Text)
    agent_name: Mapped[str | None] = mapped_column(String(128))
    srcip: Mapped[str | None] = mapped_column(String(45))  # 45 cabe um IPv6

    # Dados não confiáveis: vieram do atacante. Guardar, nunca executar ou interpretar.
    full_log: Mapped[str | None] = mapped_column(Text)
    raw_json: Mapped[str] = mapped_column(Text)

    recebido_em: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=agora_utc)


class ReputacaoIP(Base):
    """Cache das consultas de reputação: uma linha por (ip, fonte)."""

    __tablename__ = "reputacao_ip"
    __table_args__ = (UniqueConstraint("ip", "fonte"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    fonte: Mapped[str] = mapped_column(String(32))
    # Só os campos normalizados pelo schema da fonte, nunca a resposta inteira.
    resumo_json: Mapped[str] = mapped_column(Text)
    consultado_em: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=agora_utc)


class Incidente(Base):
    """Alertas da mesma origem numa janela de tempo. Ver app/incidentes.py."""

    __tablename__ = "incidentes"

    id: Mapped[int] = mapped_column(primary_key=True)
    chave: Mapped[str] = mapped_column(String(160), index=True)
    primeiro_em: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ultimo_em: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    total: Mapped[int] = mapped_column(Integer, default=0)
    nivel_max: Mapped[int] = mapped_column(Integer)
    # Preenchida pela revisão do analista; incidente decidido não recebe alertas novos.
    decisao: Mapped[str | None] = mapped_column(String(16))
    decidido_em: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IncidenteAlerta(Base):
    """Vínculo alerta -> incidente numa tabela própria: a tabela de alertas não muda (sem migração)."""

    __tablename__ = "incidente_alertas"

    alerta_id: Mapped[int] = mapped_column(ForeignKey("alertas.id"), primary_key=True)
    incidente_id: Mapped[int] = mapped_column(ForeignKey("incidentes.id"), index=True)


class Bloqueio(Base):
    """Cada resposta ativa disparada por um analista: trilha de auditoria do que foi feito."""

    __tablename__ = "bloqueios"

    id: Mapped[int] = mapped_column(primary_key=True)
    alerta_id: Mapped[int] = mapped_column(ForeignKey("alertas.id"), index=True)
    ip: Mapped[str] = mapped_column(String(45))
    agente_id: Mapped[str] = mapped_column(String(16))
    sucesso: Mapped[bool]
    detalhe: Mapped[str] = mapped_column(Text)
    executado_em: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=agora_utc)


class Analise(Base):
    """Sugestão da IA para um alerta. Só um humano muda a revisão (etapa 5)."""

    __tablename__ = "analises"

    id: Mapped[int] = mapped_column(primary_key=True)
    alerta_id: Mapped[int] = mapped_column(ForeignKey("alertas.id"), index=True)
    modelo: Mapped[str] = mapped_column(String(64))

    # sugestao: depois das políticas; sugestao_ia: como a IA respondeu.
    # Guardar as duas deixa visível o que as políticas mudaram.
    sugestao_json: Mapped[str] = mapped_column(Text)
    sugestao_ia_json: Mapped[str] = mapped_column(Text)
    ajustes_json: Mapped[str] = mapped_column(Text)

    revisao: Mapped[str] = mapped_column(String(16), default="pendente")
    revisado_em: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    correcao_json: Mapped[str | None] = mapped_column(Text)

    criada_em: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=agora_utc)
