import copy
import json
from datetime import timedelta

import pytest
from pydantic import SecretStr
from sqlalchemy import select, update

from app import enriquecimento
from app.config import settings
from app.models import ReputacaoIP, agora_utc

URL = "/api/alertas"
IP_PUBLICO_REAL = enriquecimento.ip_publico


def criar_alerta(client, auth, alerta) -> int:
    return client.post(URL, json=alerta, headers=auth).json()["id"]


def reputacao(client, auth, alerta_id):
    return client.get(f"{URL}/{alerta_id}/reputacao", headers=auth)


def test_consulta_as_duas_fontes(client, auth, alerta_ssh, fontes):
    resposta = reputacao(client, auth, criar_alerta(client, auth, alerta_ssh))

    assert resposta.status_code == 200
    corpo = resposta.json()
    assert corpo["ip"] == "203.0.113.45"
    assert corpo["publico"] is True
    abuse = corpo["fontes"]["abuseipdb"]
    vt = corpo["fontes"]["virustotal"]
    assert abuse["status"] == "ok" and abuse["em_cache"] is False
    assert abuse["dados"]["score"] == 100
    assert abuse["dados"]["total_denuncias"] == 321
    assert vt["status"] == "ok"
    assert vt["dados"]["maliciosos"] == 12
    assert vt["dados"]["reputacao"] == -35
    assert len(fontes["chamadas"]) == 2


def test_chaves_vao_no_header_de_cada_fonte(client, auth, alerta_ssh, fontes):
    reputacao(client, auth, criar_alerta(client, auth, alerta_ssh))

    por_host = {r.url.host: r for r in fontes["chamadas"]}
    abuse = por_host["api.abuseipdb.com"]
    vt = por_host["www.virustotal.com"]
    assert abuse.headers["Key"] == "chave-abuse-teste"
    assert abuse.url.params["ipAddress"] == "203.0.113.45"
    assert vt.headers["x-apikey"] == "chave-vt-teste"
    assert vt.url.path == "/api/v3/ip_addresses/203.0.113.45"


def test_guarda_so_os_campos_conhecidos(client, auth, alerta_ssh, fontes, db):
    corpo = reputacao(client, auth, criar_alerta(client, auth, alerta_ssh)).json()

    assert "reports" not in corpo["fontes"]["abuseipdb"]["dados"]
    assert "whois" not in corpo["fontes"]["virustotal"]["dados"]
    for linha in db.scalars(select(ReputacaoIP)):
        assert "ignore as instruções" not in linha.resumo_json
        assert "whois" not in linha.resumo_json


def test_segunda_consulta_usa_o_cache(client, auth, alerta_ssh, fontes):
    alerta_id = criar_alerta(client, auth, alerta_ssh)
    reputacao(client, auth, alerta_id)

    segunda = reputacao(client, auth, alerta_id).json()

    assert len(fontes["chamadas"]) == 2
    assert segunda["fontes"]["abuseipdb"]["em_cache"] is True
    assert segunda["fontes"]["virustotal"]["em_cache"] is True
    assert segunda["fontes"]["abuseipdb"]["dados"]["score"] == 100


def test_cache_vencido_consulta_de_novo(client, auth, alerta_ssh, fontes, db):
    alerta_id = criar_alerta(client, auth, alerta_ssh)
    reputacao(client, auth, alerta_id)
    antigo = agora_utc() - timedelta(hours=settings.cache_reputacao_horas + 1)
    db.execute(update(ReputacaoIP).values(consultado_em=antigo))
    db.commit()

    segunda = reputacao(client, auth, alerta_id).json()

    assert len(fontes["chamadas"]) == 4
    assert segunda["fontes"]["abuseipdb"]["em_cache"] is False


def test_ip_nao_publico_nao_sai_para_a_internet(client, auth, alerta_ssh, fontes, monkeypatch):
    monkeypatch.setattr(enriquecimento, "ip_publico", IP_PUBLICO_REAL)

    corpo = reputacao(client, auth, criar_alerta(client, auth, alerta_ssh)).json()

    assert corpo == {"ip": "203.0.113.45", "publico": False, "fontes": {}}
    assert fontes["chamadas"] == []


def test_alerta_sem_srcip(client, auth, alerta_ssh, fontes):
    alerta = copy.deepcopy(alerta_ssh)
    del alerta["data"]["srcip"]

    corpo = reputacao(client, auth, criar_alerta(client, auth, alerta)).json()

    assert corpo == {"ip": None, "publico": False, "fontes": {}}
    assert fontes["chamadas"] == []


def test_fonte_sem_chave_fica_nao_configurada(client, auth, alerta_ssh, fontes, monkeypatch):
    monkeypatch.setattr(settings, "virustotal_api_key", None)

    corpo = reputacao(client, auth, criar_alerta(client, auth, alerta_ssh)).json()

    assert corpo["fontes"]["virustotal"]["status"] == "nao_configurado"
    assert corpo["fontes"]["abuseipdb"]["status"] == "ok"
    assert [r.url.host for r in fontes["chamadas"]] == ["api.abuseipdb.com"]


def test_limite_excedido_nao_grava_cache(client, auth, alerta_ssh, fontes, db):
    fontes["abuseipdb"] = (429, {"errors": [{"detail": "Daily rate limit exceeded"}]})

    corpo = reputacao(client, auth, criar_alerta(client, auth, alerta_ssh)).json()

    assert corpo["fontes"]["abuseipdb"]["status"] == "limite_excedido"
    assert corpo["fontes"]["virustotal"]["status"] == "ok"
    fontes_em_cache = db.scalars(select(ReputacaoIP.fonte)).all()
    assert fontes_em_cache == ["virustotal"]


def test_erro_http_da_fonte(client, auth, alerta_ssh, fontes):
    fontes["virustotal"] = (500, {})

    corpo = reputacao(client, auth, criar_alerta(client, auth, alerta_ssh)).json()

    assert corpo["fontes"]["virustotal"] == {
        "status": "erro",
        "em_cache": False,
        "consultado_em": None,
        "dados": None,
        "erro": "HTTP 500",
    }


def test_resposta_fora_do_formato_vira_erro(client, auth, alerta_ssh, fontes):
    fontes["abuseipdb"] = (200, {"inesperado": True})

    corpo = reputacao(client, auth, criar_alerta(client, auth, alerta_ssh)).json()

    assert corpo["fontes"]["abuseipdb"]["status"] == "erro"
    assert corpo["fontes"]["abuseipdb"]["erro"] == "KeyError"


def test_falha_de_rede_vira_erro(client, auth, alerta_ssh, monkeypatch):
    # Sem a fixture "fontes": o cliente HTTP dos testes recusa qualquer conexão.
    monkeypatch.setattr(settings, "abuseipdb_api_key", SecretStr("chave-abuse-teste"))
    monkeypatch.setattr(enriquecimento, "ip_publico", lambda ip: True)

    corpo = reputacao(client, auth, criar_alerta(client, auth, alerta_ssh)).json()

    assert corpo["fontes"]["abuseipdb"]["status"] == "erro"
    assert corpo["fontes"]["abuseipdb"]["erro"] == "ConnectError"


def test_alerta_inexistente_retorna_404(client, auth):
    assert reputacao(client, auth, 999).status_code == 404


def test_reputacao_sem_token_retorna_401(client):
    assert client.get(f"{URL}/1/reputacao").status_code == 401


@pytest.mark.parametrize(
    ("ip", "esperado"),
    [
        ("8.8.8.8", True),
        ("198.51.100.23", False),  # documentação
        ("10.0.0.5", False),  # rede privada
        ("127.0.0.1", False),
        ("fe80::1", False),
    ],
)
def test_ip_publico(ip, esperado):
    assert IP_PUBLICO_REAL(ip) is esperado
