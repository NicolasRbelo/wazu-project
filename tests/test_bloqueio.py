import copy
import json

URL = "/api/alertas"
NOTA = "Força bruta confirmada, bloquear na origem."
CORRECAO_BLOQUEIO = {"classificacao": "verdadeiro_positivo", "severidade": "alta", "acao_sugerida": "bloquear_ip"}


def alerta_decidido(client, auth, alerta, decisao="corrigida", correcao=CORRECAO_BLOQUEIO, wazuh_id=None):
    if wazuh_id:
        alerta = copy.deepcopy(alerta)
        alerta["id"] = wazuh_id
    alerta_id = client.post(URL, json=alerta, headers=auth).json()["id"]
    client.post(f"{URL}/{alerta_id}/analise", headers=auth)
    corpo = {"decisao": decisao}
    if decisao == "corrigida":
        corpo |= {"correcao": correcao, "nota": NOTA}
    elif decisao == "descartada":
        corpo |= {"nota": NOTA}
    client.post(f"{URL}/{alerta_id}/revisao", headers=auth, json=corpo)
    return alerta_id


def bloquear(client, auth, alerta_id):
    return client.post(f"{URL}/{alerta_id}/bloqueio", headers=auth)


def test_bloqueio_dispara_firewall_drop_no_agente(client, auth, alerta_ssh, gemini, wazuh_api):
    alerta_id = alerta_decidido(client, auth, alerta_ssh)

    resposta = bloquear(client, auth, alerta_id)

    assert resposta.status_code == 201
    corpo = resposta.json()
    assert corpo["sucesso"] is True
    assert (corpo["ip"], corpo["agente_id"]) == ("203.0.113.45", "001")
    autenticacao, comando = wazuh_api["chamadas"]
    assert autenticacao.headers["Authorization"].startswith("Basic ")
    assert comando.method == "PUT"
    assert comando.url.path == "/active-response"
    assert comando.url.params["agents_list"] == "001"
    assert comando.headers["Authorization"] == "Bearer jwt-falso"
    assert json.loads(comando.content) == {"command": "!firewall-drop", "alert": {"data": {"srcip": "203.0.113.45"}}}


def test_aprovar_sugestao_de_bloqueio_tambem_permite(client, auth, alerta_ssh, gemini, wazuh_api):
    from falsos import SUGESTAO_PADRAO, resposta_gemini

    gemini["gemini"] = (200, resposta_gemini({**SUGESTAO_PADRAO, "acao_sugerida": "bloquear_ip"}))
    alerta_id = alerta_decidido(client, auth, alerta_ssh, decisao="aprovada")

    assert bloquear(client, auth, alerta_id).status_code == 201


def test_sem_decisao_de_bloquear_nao_bloqueia(client, auth, alerta_ssh, gemini, wazuh_api):
    # A IA sugeriu "investigar" e o analista aprovou: ninguém decidiu bloquear.
    aprovado = alerta_decidido(client, auth, alerta_ssh, decisao="aprovada")
    pendente = client.post(URL, json={**alerta_ssh, "id": "9.9"}, headers=auth).json()["id"]
    client.post(f"{URL}/{pendente}/analise", headers=auth)

    assert bloquear(client, auth, aprovado).status_code == 409
    assert bloquear(client, auth, pendente).status_code == 409
    assert wazuh_api["chamadas"] == []


def test_alerta_do_manager_nao_tem_agente_para_bloquear(client, auth, alerta_ssh, gemini, wazuh_api):
    alerta = copy.deepcopy(alerta_ssh)
    alerta["agent"]["id"] = "000"
    alerta_id = alerta_decidido(client, auth, alerta)

    assert bloquear(client, auth, alerta_id).status_code == 409
    assert wazuh_api["chamadas"] == []


def test_ip_protegido_nunca_e_bloqueado(client, auth, alerta_ssh, gemini, wazuh_api, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "bloqueio_protegidos", "10.0.0.0/8, 203.0.113.0/24")
    alerta_id = alerta_decidido(client, auth, alerta_ssh)

    resposta = bloquear(client, auth, alerta_id)

    assert resposta.status_code == 409
    assert "protegido" in resposta.json()["detail"]
    assert wazuh_api["chamadas"] == []


def test_sem_api_do_wazuh_configurada_retorna_503(client, auth, alerta_ssh, gemini):
    alerta_id = alerta_decidido(client, auth, alerta_ssh)

    assert bloquear(client, auth, alerta_id).status_code == 503


def test_falha_na_api_do_wazuh_fica_registrada(client, auth, alerta_ssh, gemini, wazuh_api):
    wazuh_api["active_response"] = (200, {"data": {"total_affected_items": 0, "failed_items": [{"error": {"code": 1707}}]}, "error": 1})
    alerta_id = alerta_decidido(client, auth, alerta_ssh)

    resposta = bloquear(client, auth, alerta_id)

    assert resposta.status_code == 502
    assert client.get(f"{URL}/{alerta_id}/bloqueio", headers=auth).status_code == 404


def test_segundo_pedido_nao_reenvia_o_comando(client, auth, alerta_ssh, gemini, wazuh_api):
    alerta_id = alerta_decidido(client, auth, alerta_ssh)
    primeiro = bloquear(client, auth, alerta_id)

    segundo = bloquear(client, auth, alerta_id)

    assert segundo.status_code == 200
    assert segundo.json()["id"] == primeiro.json()["id"]
    assert len(wazuh_api["chamadas"]) == 2  # só a autenticação e o comando do primeiro pedido
    consulta = client.get(f"{URL}/{alerta_id}/bloqueio", headers=auth)
    assert consulta.status_code == 200
    assert consulta.json()["sucesso"] is True


def test_bloqueio_exige_token(client):
    assert client.post(f"{URL}/1/bloqueio").status_code == 401
