import copy
import json

from sqlalchemy import func, select

from app.models import Alerta

URL = "/api/alertas"


def contar_alertas(db):
    return db.scalar(select(func.count()).select_from(Alerta))


def test_alerta_valido_retorna_201(client, auth, alerta_ssh):
    resposta = client.post(URL, json=alerta_ssh, headers=auth)

    assert resposta.status_code == 201
    corpo = resposta.json()
    assert corpo["wazuh_id"] == alerta_ssh["id"]
    assert corpo["rule_level"] == 5
    assert corpo["agent_name"] == "srv-lab-01"
    assert corpo["srcip"] == "203.0.113.45"
    assert "raw_json" not in corpo


def test_sem_token_retorna_401(client, alerta_ssh, db):
    resposta = client.post(URL, json=alerta_ssh)

    assert resposta.status_code == 401
    assert resposta.headers["www-authenticate"] == "Bearer"
    assert contar_alertas(db) == 0


def test_token_errado_retorna_401(client, alerta_ssh):
    resposta = client.post(URL, json=alerta_ssh, headers={"Authorization": "Bearer errado"})

    assert resposta.status_code == 401


def test_alerta_duplicado_grava_um_registro(client, auth, alerta_ssh, db):
    primeira = client.post(URL, json=alerta_ssh, headers=auth)
    segunda = client.post(URL, json=alerta_ssh, headers=auth)

    assert primeira.status_code == 201
    assert segunda.status_code == 200
    assert segunda.json()["id"] == primeira.json()["id"]
    assert contar_alertas(db) == 1


def test_alerta_sem_srcip_e_salvo(client, auth, alerta_ssh):
    alerta = copy.deepcopy(alerta_ssh)
    del alerta["data"]["srcip"]

    resposta = client.post(URL, json=alerta, headers=auth)

    assert resposta.status_code == 201
    assert resposta.json()["srcip"] is None


def test_srcip_que_nao_e_ip_vira_none(client, auth, alerta_ssh, db):
    alerta = copy.deepcopy(alerta_ssh)
    alerta["data"]["srcip"] = "'; DROP TABLE alertas; --"

    resposta = client.post(URL, json=alerta, headers=auth)

    assert resposta.status_code == 201
    assert resposta.json()["srcip"] is None
    # O valor original continua preservado para a análise.
    salvo = db.scalar(select(Alerta))
    assert json.loads(salvo.raw_json)["data"]["srcip"] == alerta["data"]["srcip"]


def test_corpo_invalido_retorna_422(client, auth, db):
    resposta = client.post(URL, json={"id": "123"}, headers=auth)  # sem rule

    assert resposta.status_code == 422
    assert contar_alertas(db) == 0


def test_raw_json_guarda_o_alerta_original(client, auth, alerta_ssh, db):
    client.post(URL, json=alerta_ssh, headers=auth)

    salvo = db.scalar(select(Alerta))
    assert json.loads(salvo.raw_json) == alerta_ssh


def test_listagem_sem_raw_json_e_mais_recente_primeiro(client, auth, alerta_ssh):
    segundo = copy.deepcopy(alerta_ssh)
    segundo["id"] = "1793268999.200000"
    client.post(URL, json=alerta_ssh, headers=auth)
    client.post(URL, json=segundo, headers=auth)

    resposta = client.get(URL, headers=auth)

    assert resposta.status_code == 200
    alertas = resposta.json()
    assert [a["wazuh_id"] for a in alertas] == [segundo["id"], alerta_ssh["id"]]
    assert all("raw_json" not in a for a in alertas)


def test_listagem_sem_token_retorna_401(client):
    assert client.get(URL).status_code == 401
