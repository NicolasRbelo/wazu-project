import copy
import json
from datetime import timedelta

from sqlalchemy import update

from app.config import settings
from app.models import Incidente

URL = "/api/alertas"
NOTA = "Origem conhecida do laboratório, teste autorizado."


def enviar(client, auth, base, wazuh_id, srcip="203.0.113.45", agente=None, regra=None):
    alerta = copy.deepcopy(base)
    alerta["id"] = wazuh_id
    if srcip is None:
        alerta["data"].pop("srcip", None)
    else:
        alerta["data"]["srcip"] = srcip
    if agente:
        alerta["agent"]["name"] = agente
    if regra:
        alerta["rule"]["id"] = regra
    return client.post(URL, json=alerta, headers=auth).json()["id"]


def por_id(client, auth) -> dict[int, dict]:
    return {a["id"]: a for a in client.get(URL, headers=auth).json()}


def envelhecer_incidentes(db, minutos):
    """Simula a passagem do tempo empurrando o último alerta dos incidentes para o passado."""
    for incidente in db.query(Incidente).all():
        db.execute(
            update(Incidente)
            .where(Incidente.id == incidente.id)
            .values(ultimo_em=incidente.ultimo_em - timedelta(minutes=minutos))
        )
    db.commit()


def test_alertas_do_mesmo_ip_viram_um_incidente(client, auth, alerta_ssh):
    a = enviar(client, auth, alerta_ssh, "1.1")
    b = enviar(client, auth, alerta_ssh, "1.2")
    c = enviar(client, auth, alerta_ssh, "1.3", srcip="198.51.100.9")

    lista = por_id(client, auth)

    assert lista[a]["incidente"]["id"] == lista[b]["incidente"]["id"]
    assert lista[a]["incidente"]["total"] == 2
    assert lista[c]["incidente"]["id"] != lista[a]["incidente"]["id"]
    assert lista[c]["incidente"]["total"] == 1


def test_fora_da_janela_abre_incidente_novo(client, auth, alerta_ssh, db):
    a = enviar(client, auth, alerta_ssh, "2.1")
    envelhecer_incidentes(db, settings.incidente_janela_minutos + 1)

    b = enviar(client, auth, alerta_ssh, "2.2")

    lista = por_id(client, auth)
    assert lista[a]["incidente"]["id"] != lista[b]["incidente"]["id"]


def test_sem_ip_agrupa_por_regra_e_agente(client, auth, alerta_ssh):
    a = enviar(client, auth, alerta_ssh, "3.1", srcip=None, agente="srv-lab-02")
    b = enviar(client, auth, alerta_ssh, "3.2", srcip=None, agente="srv-lab-02")
    c = enviar(client, auth, alerta_ssh, "3.3", srcip=None, agente="srv-web-01")

    lista = por_id(client, auth)

    assert lista[a]["incidente"]["id"] == lista[b]["incidente"]["id"]
    assert lista[c]["incidente"]["id"] != lista[a]["incidente"]["id"]


def test_decisao_vale_para_o_incidente_todo(client, auth, alerta_ssh, gemini):
    a = enviar(client, auth, alerta_ssh, "4.1")
    b = enviar(client, auth, alerta_ssh, "4.2")
    client.post(f"{URL}/{a}/analise", headers=auth)

    client.post(f"{URL}/{a}/revisao", headers=auth, json={"decisao": "descartada", "nota": NOTA})

    lista = por_id(client, auth)
    assert lista[a]["incidente"]["decisao"] == "descartada"
    assert lista[b]["incidente"]["decisao"] == "descartada"
    assert lista[b]["analise"] is None  # b não foi analisado, mas saiu da fila junto


def test_incidente_decidido_nao_recebe_alertas_novos(client, auth, alerta_ssh, gemini):
    a = enviar(client, auth, alerta_ssh, "5.1")
    client.post(f"{URL}/{a}/analise", headers=auth)
    client.post(f"{URL}/{a}/revisao", headers=auth, json={"decisao": "aprovada"})

    b = enviar(client, auth, alerta_ssh, "5.2")

    lista = por_id(client, auth)
    assert lista[b]["incidente"]["id"] != lista[a]["incidente"]["id"]
    assert lista[b]["incidente"]["decisao"] is None


def test_refazer_a_analise_reabre_o_incidente(client, auth, alerta_ssh, gemini):
    a = enviar(client, auth, alerta_ssh, "6.1")
    client.post(f"{URL}/{a}/analise", headers=auth)
    client.post(f"{URL}/{a}/revisao", headers=auth, json={"decisao": "aprovada"})

    client.post(f"{URL}/{a}/analise", headers=auth, params={"refazer": True})

    assert por_id(client, auth)[a]["incidente"]["decisao"] is None


def test_ia_recebe_o_tamanho_do_incidente(client, auth, alerta_ssh, gemini):
    enviar(client, auth, alerta_ssh, "7.1", regra="5710")
    b = enviar(client, auth, alerta_ssh, "7.2", regra="5712")

    client.post(f"{URL}/{b}/analise", headers=auth)

    (pedido,) = [r for r in gemini["chamadas"] if r.url.host == "generativelanguage.googleapis.com"]
    texto = json.loads(pedido.content)["contents"][0]["parts"][0]["text"]
    dados = json.loads(texto.split(">\n", 1)[1].rsplit("\n</", 1)[0])
    assert dados["incidente"]["alertas_no_incidente"] == 2
    assert dados["incidente"]["regras"] == ["5710", "5712"]


def test_alerta_isolado_nao_manda_incidente_para_a_ia(client, auth, alerta_ssh, gemini):
    a = enviar(client, auth, alerta_ssh, "8.1")

    client.post(f"{URL}/{a}/analise", headers=auth)

    (pedido,) = [r for r in gemini["chamadas"] if r.url.host == "generativelanguage.googleapis.com"]
    texto = json.loads(pedido.content)["contents"][0]["parts"][0]["text"]
    assert '"incidente": null' in texto
