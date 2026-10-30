"""Reputação de IPs no AbuseIPDB e no VirusTotal, com cache no banco."""
import ipaddress
import json
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone

import httpx
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.models import ReputacaoIP, agora_utc
from app.schemas import ReputacaoAbuseIPDB, ReputacaoSaida, ReputacaoVirusTotal, ResultadoFonte

TIMEOUT = 10.0

Consulta = Callable[[httpx.Client, str, str], dict]


def get_http_client() -> Iterator[httpx.Client]:
    with httpx.Client(timeout=TIMEOUT) as cliente:
        yield cliente


def ip_publico(ip: str) -> bool:
    """Só IPs roteáveis na internet são consultados: IP interno não vaza para terceiros."""
    return ipaddress.ip_address(ip).is_global


def consultar_abuseipdb(cliente: httpx.Client, chave: str, ip: str) -> dict:
    resposta = cliente.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": 90},
        headers={"Key": chave, "Accept": "application/json"},
    )
    resposta.raise_for_status()
    return ReputacaoAbuseIPDB.model_validate(resposta.json()["data"]).model_dump(mode="json")


def consultar_virustotal(cliente: httpx.Client, chave: str, ip: str) -> dict:
    # ip já vem normalizado por ipaddress (AlertaWazuh.srcip), seguro para ir no caminho da URL.
    resposta = cliente.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": chave},
    )
    resposta.raise_for_status()
    atributos = resposta.json()["data"]["attributes"]
    estatisticas = atributos["last_analysis_stats"]
    return ReputacaoVirusTotal(
        maliciosos=estatisticas["malicious"],
        suspeitos=estatisticas["suspicious"],
        inofensivos=estatisticas["harmless"],
        nao_detectados=estatisticas["undetected"],
        reputacao=atributos.get("reputation"),
        pais=atributos.get("country"),
        dono_as=atributos.get("as_owner"),
        rede=atributos.get("network"),
    ).model_dump(mode="json")


def _fontes() -> list[tuple[str, Consulta, SecretStr | None]]:
    # Lido a cada chamada, e não na importação, para os testes poderem trocar as chaves.
    return [
        ("abuseipdb", consultar_abuseipdb, settings.abuseipdb_api_key),
        ("virustotal", consultar_virustotal, settings.virustotal_api_key),
    ]


def _como_utc(momento: datetime) -> datetime:
    # O SQLite devolve datetime sem fuso; o que gravamos é sempre UTC.
    return momento if momento.tzinfo else momento.replace(tzinfo=timezone.utc)


def _consultar_fonte(
    db: Session,
    cliente: httpx.Client,
    fonte: str,
    consulta: Consulta,
    chave: SecretStr | None,
    ip: str,
) -> ResultadoFonte:
    if chave is None:
        return ResultadoFonte(status="nao_configurado")

    cache = db.scalar(
        select(ReputacaoIP).where(ReputacaoIP.ip == ip, ReputacaoIP.fonte == fonte)
    )
    validade = timedelta(hours=settings.cache_reputacao_horas)
    if cache is not None and agora_utc() - _como_utc(cache.consultado_em) < validade:
        return ResultadoFonte(
            status="ok",
            em_cache=True,
            consultado_em=_como_utc(cache.consultado_em),
            dados=json.loads(cache.resumo_json),
        )

    try:
        dados = consulta(cliente, chave.get_secret_value(), ip)
    except httpx.HTTPStatusError as erro:
        if erro.response.status_code == 429:
            return ResultadoFonte(status="limite_excedido")
        return ResultadoFonte(status="erro", erro=f"HTTP {erro.response.status_code}")
    except (httpx.HTTPError, KeyError, TypeError, ValueError) as erro:
        # Só o tipo do erro: a mensagem poderia trazer trechos da resposta da fonte.
        return ResultadoFonte(status="erro", erro=type(erro).__name__)

    agora = agora_utc()
    if cache is None:
        cache = ReputacaoIP(ip=ip, fonte=fonte)
        db.add(cache)
    cache.resumo_json = json.dumps(dados, ensure_ascii=False)
    cache.consultado_em = agora
    try:
        db.commit()
    except IntegrityError:
        # Outra requisição gravou o mesmo (ip, fonte) ao mesmo tempo: o resultado continua válido.
        db.rollback()
    return ResultadoFonte(status="ok", consultado_em=agora, dados=dados)


def obter_reputacao(db: Session, cliente: httpx.Client, ip: str | None) -> ReputacaoSaida:
    if ip is None or not ip_publico(ip):
        return ReputacaoSaida(ip=ip, publico=False, fontes={})
    fontes = {
        nome: _consultar_fonte(db, cliente, nome, consulta, chave, ip)
        for nome, consulta, chave in _fontes()
    }
    return ReputacaoSaida(ip=ip, publico=True, fontes=fontes)
