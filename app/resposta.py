"""Resposta ativa com aprovação humana: bloquear o IP de origem no agente atacado.

Usa a API do Wazuh para disparar o `firewall-drop` (iptables DROP) no agente que
gerou o alerta. Só roda depois que o analista decidiu "bloquear_ip" e confirmou no
painel: a IA nunca dispara isto. O bloqueio dura até ser removido no agente.
"""
import ipaddress
from collections.abc import Iterator

import httpx

from app.config import settings

TIMEOUT = 15.0


class ErroBloqueio(Exception):
    """A API do Wazuh recusou ou não respondeu; a mensagem diz o porquê, sem segredos."""


def get_cliente_wazuh() -> Iterator[httpx.Client]:
    # Cliente próprio: a verificação de TLS da API do Wazuh é configurável (o lab usa certificado próprio).
    with httpx.Client(timeout=TIMEOUT, verify=settings.wazuh_api_verificar_tls) as cliente:
        yield cliente


def configurado() -> bool:
    return bool(settings.wazuh_api_url and settings.wazuh_api_usuario and settings.wazuh_api_senha)


def protegido(ip: str) -> bool:
    """IPs que nunca são bloqueados (o próprio manager, a API, o gateway do lab...)."""
    alvo = ipaddress.ip_address(ip)
    for item in filter(None, (p.strip() for p in settings.bloqueio_protegidos.split(","))):
        if alvo in ipaddress.ip_network(item, strict=False):
            return True
    return alvo.is_loopback or alvo.is_unspecified


def bloquear(cliente: httpx.Client, ip: str, agente_id: str) -> str:
    """Dispara o firewall-drop no agente. Devolve a mensagem da API do Wazuh."""
    base = settings.wazuh_api_url.rstrip("/")
    try:
        autenticacao = cliente.post(
            f"{base}/security/user/authenticate",
            params={"raw": "true"},
            auth=(settings.wazuh_api_usuario, settings.wazuh_api_senha.get_secret_value()),
        )
        if autenticacao.status_code != 200:
            raise ErroBloqueio(f"autenticação na API do Wazuh falhou (HTTP {autenticacao.status_code})")
        resposta = cliente.put(
            f"{base}/active-response",
            params={"agents_list": agente_id},
            headers={"Authorization": f"Bearer {autenticacao.text.strip()}"},
            # O firewall-drop lê o IP de alert.data.srcip, como num alerta de verdade.
            json={"command": "!firewall-drop", "alert": {"data": {"srcip": ip}}},
        )
    except httpx.HTTPError as erro:
        raise ErroBloqueio(f"API do Wazuh não respondeu ({type(erro).__name__})") from erro
    try:
        corpo = resposta.json()
    except ValueError:
        corpo = {}
    dados = corpo.get("data") or {}
    if resposta.status_code != 200 or corpo.get("error") != 0 or dados.get("total_affected_items") != 1:
        raise ErroBloqueio(f"API do Wazuh não aplicou o bloqueio (HTTP {resposta.status_code})")
    return str(corpo.get("message", "comando enviado"))[:200]
