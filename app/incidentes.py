"""Agrupamento de alertas em incidentes.

Um incidente junta os alertas do mesmo IP de origem (ou, sem IP, da mesma regra no
mesmo agente) enquanto chegam com menos de INCIDENTE_JANELA_MINUTOS entre si. O
analista decide o incidente uma vez, em vez de cada uma das dezenas de alertas de
uma força bruta. Incidente decidido não recebe alertas novos: se o ataque continua,
abre-se outro, que volta para a fila.
"""
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import Alerta, Incidente, IncidenteAlerta
from app.schemas import ResumoIncidente


def chave_de(alerta: Alerta) -> str:
    if alerta.srcip:
        return f"ip:{alerta.srcip}"
    return f"regra:{alerta.rule_id}@{alerta.agent_name or '-'}"


def agrupar(db: Session, alerta: Alerta) -> Incidente:
    """Coloca um alerta recém-gravado no incidente aberto da sua chave, ou abre um novo."""
    chave = chave_de(alerta)
    limite = alerta.recebido_em - timedelta(minutes=settings.incidente_janela_minutos)
    incidente = db.scalar(
        select(Incidente)
        .where(Incidente.chave == chave, Incidente.decisao.is_(None), Incidente.ultimo_em >= limite)
        .order_by(Incidente.ultimo_em.desc())
        .limit(1)
    )
    if incidente is None:
        incidente = Incidente(
            chave=chave, primeiro_em=alerta.recebido_em, ultimo_em=alerta.recebido_em,
            total=0, nivel_max=alerta.rule_level,
        )
        db.add(incidente)
        db.flush()
    incidente.total += 1
    incidente.ultimo_em = alerta.recebido_em
    incidente.nivel_max = max(incidente.nivel_max, alerta.rule_level)
    db.add(IncidenteAlerta(alerta_id=alerta.id, incidente_id=incidente.id))
    return incidente


def do_alerta(db: Session, alerta_id: int) -> Incidente | None:
    vinculo = db.get(IncidenteAlerta, alerta_id)
    return db.get(Incidente, vinculo.incidente_id) if vinculo else None


def resumo(incidente: Incidente) -> ResumoIncidente:
    return ResumoIncidente.model_validate(incidente)


def resumos_por_alerta(db: Session, alerta_ids: list[int]) -> dict[int, ResumoIncidente]:
    if not alerta_ids:
        return {}
    linhas = db.execute(
        select(IncidenteAlerta.alerta_id, Incidente)
        .join(Incidente, Incidente.id == IncidenteAlerta.incidente_id)
        .where(IncidenteAlerta.alerta_id.in_(alerta_ids))
    ).all()
    return {alerta_id: resumo(incidente) for alerta_id, incidente in linhas}


def contexto(db: Session, alerta_id: int) -> dict | None:
    """O que a IA recebe sobre o incidente. Só contagens e campos do Wazuh, nada do atacante."""
    incidente = do_alerta(db, alerta_id)
    if incidente is None or incidente.total < 2:
        return None
    membros = (
        select(Alerta)
        .join(IncidenteAlerta, IncidenteAlerta.alerta_id == Alerta.id)
        .where(IncidenteAlerta.incidente_id == incidente.id)
    )
    alertas = db.scalars(membros).all()
    return {
        "alertas_no_incidente": incidente.total,
        "regras": sorted({a.rule_id for a in alertas}),
        "agentes": sorted({a.agent_name for a in alertas if a.agent_name}),
        "primeiro_em": incidente.primeiro_em.isoformat(),
        "ultimo_em": incidente.ultimo_em.isoformat(),
    }
