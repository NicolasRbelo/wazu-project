import copy
import json

import pytest

from falsos import SUGESTAO_PADRAO, resposta_gemini

URL = "/api/alertas"
NOTA = "Origem conhecida do laboratório, teste autorizado."
SUGESTAO_DESCARTAR = {**SUGESTAO_PADRAO, "classificacao": "falso_positivo", "acao_sugerida": "descartar"}


def criar_alerta(client, auth, alerta) -> int:
    return client.post(URL, json=alerta, headers=auth).json()["id"]


def analisar(client, auth, alerta_id):
    return client.post(f"{URL}/{alerta_id}/analise", headers=auth)


def revisar(client, auth, alerta_id, **corpo):
    return client.post(f"{URL}/{alerta_id}/revisao", headers=auth, json=corpo)


def alerta_analisado(client, auth, alerta) -> int:
    alerta_id = criar_alerta(client, auth, alerta)
    assert analisar(client, auth, alerta_id).status_code == 201
    return alerta_id


def feedbacks(client, auth) -> list[dict]:
    return client.get("/api/feedback", headers=auth).json()


def corrigir(classificacao="verdadeiro_positivo", severidade="media", acao="investigar"):
    return {"classificacao": classificacao, "severidade": severidade, "acao_sugerida": acao}


def test_aprovar(client, auth, alerta_ssh, gemini):
    alerta_id = alerta_analisado(client, auth, alerta_ssh)

    resposta = revisar(client, auth, alerta_id, decisao="aprovada")

    assert resposta.status_code == 200
    corpo = resposta.json()
    assert corpo["revisao"] == "aprovada"
    assert corpo["revisado_em"] is not None
    (item,) = feedbacks(client, auth)
    assert item["importancia"] == "baixa"
    assert item["uso"] == "exemplo"
    assert item["final"] == corrigir()


def test_corrigir_a_classificacao_tem_importancia_alta(client, auth, alerta_ssh, gemini):
    alerta_id = alerta_analisado(client, auth, alerta_ssh)

    corpo = revisar(
        client, auth, alerta_id, decisao="corrigida",
        correcao=corrigir("inconclusivo", "media", "investigar"), nota=NOTA,
    ).json()

    assert corpo["revisao"] == "corrigida"
    assert corpo["correcao"]["classificacao"] == "inconclusivo"
    assert corpo["nota"] == NOTA
    (item,) = feedbacks(client, auth)
    assert item["importancia"] == "alta"
    assert item["nota"] == NOTA


def test_corrigir_so_a_acao_tem_importancia_media(client, auth, alerta_ssh, gemini):
    alerta_id = alerta_analisado(client, auth, alerta_ssh)

    revisar(client, auth, alerta_id, decisao="corrigida", correcao=corrigir(acao="bloquear_ip"), nota=NOTA)

    assert feedbacks(client, auth)[0]["importancia"] == "media"


def test_severidade_errada_em_dois_niveis_tem_importancia_alta(client, auth, alerta_ssh, gemini):
    alerta_id = alerta_analisado(client, auth, alerta_ssh)

    revisar(client, auth, alerta_id, decisao="corrigida", correcao=corrigir(severidade="critica"), nota=NOTA)

    assert feedbacks(client, auth)[0]["importancia"] == "alta"


@pytest.mark.parametrize(
    "corpo",
    [
        {"decisao": "corrigida", "correcao": corrigir(acao="bloquear_ip")},  # sem nota
        {"decisao": "corrigida", "correcao": corrigir(acao="bloquear_ip"), "nota": "curta"},
        {"decisao": "corrigida", "nota": NOTA},  # sem os campos corrigidos
        {"decisao": "descartada"},  # sem nota
        {"decisao": "aprovada", "correcao": corrigir(acao="bloquear_ip")},
        {"decisao": "fechada", "nota": NOTA},
    ],
)
def test_revisao_invalida_retorna_422(client, auth, alerta_ssh, gemini, corpo):
    alerta_id = alerta_analisado(client, auth, alerta_ssh)

    assert revisar(client, auth, alerta_id, **corpo).status_code == 422
    assert feedbacks(client, auth) == []


def test_correcao_igual_a_sugestao_retorna_422(client, auth, alerta_ssh, gemini):
    alerta_id = alerta_analisado(client, auth, alerta_ssh)

    resposta = revisar(client, auth, alerta_id, decisao="corrigida", correcao=corrigir(), nota=NOTA)

    assert resposta.status_code == 422


def test_descartar_vira_falso_positivo_no_feedback(client, auth, alerta_ssh, gemini):
    alerta_id = alerta_analisado(client, auth, alerta_ssh)

    assert revisar(client, auth, alerta_id, decisao="descartada", nota=NOTA).json()["revisao"] == "descartada"

    (item,) = feedbacks(client, auth)
    assert item["final"]["classificacao"] == "falso_positivo"
    assert item["final"]["acao_sugerida"] == "descartar"
    assert item["importancia"] == "alta"  # a IA tinha dito verdadeiro positivo
    assert item["uso"] == "exemplo"


def test_descartar_alerta_com_manipulacao_vai_para_quarentena(client, auth, alerta_injecao, gemini):
    alerta_id = alerta_analisado(client, auth, alerta_injecao)

    revisar(client, auth, alerta_id, decisao="descartada", nota=NOTA)

    (item,) = feedbacks(client, auth)
    assert item["uso"] == "quarentena"
    assert "manipulação" in item["motivo_uso"]


def test_descartar_ip_malicioso_vai_para_quarentena(client, auth, alerta_ssh, gemini, fontes):
    alerta_id = alerta_analisado(client, auth, alerta_ssh)

    revisar(client, auth, alerta_id, decisao="descartada", nota=NOTA)

    assert feedbacks(client, auth)[0]["uso"] == "quarentena"


def test_feedback_que_contradiz_exemplo_vai_para_quarentena(client, auth, alerta_ssh, gemini):
    primeiro = alerta_analisado(client, auth, alerta_ssh)
    revisar(client, auth, primeiro, decisao="descartada", nota=NOTA)
    segundo_alerta = copy.deepcopy(alerta_ssh)
    segundo_alerta["id"] = "1793270000.000001"
    segundo = alerta_analisado(client, auth, segundo_alerta)

    revisar(client, auth, segundo, decisao="aprovada")

    recente, antigo = feedbacks(client, auth)
    assert antigo["uso"] == "exemplo"
    assert recente["uso"] == "quarentena"
    assert "Contradiz" in recente["motivo_uso"]


def test_feedback_nao_guarda_log_nem_ip(client, auth, alerta_injecao, gemini, feedback_temporario):
    alerta_id = alerta_analisado(client, auth, alerta_injecao)

    revisar(client, auth, alerta_id, decisao="corrigida", correcao=corrigir(acao="bloquear_ip"), nota=NOTA)

    conteudo = feedback_temporario.read_text(encoding="utf-8")
    assert "ignore as instruções" not in conteudo
    assert alerta_injecao["data"]["srcip"] not in conteudo


def test_revisar_sem_analise_retorna_409(client, auth, alerta_ssh, gemini):
    alerta_id = criar_alerta(client, auth, alerta_ssh)

    assert revisar(client, auth, alerta_id, decisao="aprovada").status_code == 409


def test_revisar_duas_vezes_retorna_409(client, auth, alerta_ssh, gemini):
    alerta_id = alerta_analisado(client, auth, alerta_ssh)
    revisar(client, auth, alerta_id, decisao="aprovada")

    assert revisar(client, auth, alerta_id, decisao="descartada", nota=NOTA).status_code == 409
    assert len(feedbacks(client, auth)) == 1


def test_revisao_aparece_na_consulta_da_analise(client, auth, alerta_ssh, gemini):
    alerta_id = alerta_analisado(client, auth, alerta_ssh)
    revisar(client, auth, alerta_id, decisao="corrigida", correcao=corrigir(acao="bloquear_ip"), nota=NOTA)

    corpo = client.get(f"{URL}/{alerta_id}/analise", headers=auth).json()

    assert corpo["revisao"] == "corrigida"
    assert corpo["correcao"]["acao_sugerida"] == "bloquear_ip"


def _sistema_do_ultimo_pedido(rede) -> str:
    pedidos = [r for r in rede["chamadas"] if r.url.host == "generativelanguage.googleapis.com"]
    return json.loads(pedidos[-1].content)["systemInstruction"]["parts"][0]["text"]


def test_exemplos_aceitos_entram_no_prompt_da_mesma_regra(client, auth, alerta_ssh, gemini):
    primeiro = alerta_analisado(client, auth, alerta_ssh)
    revisar(client, auth, primeiro, decisao="corrigida", correcao=corrigir(acao="bloquear_ip"), nota=NOTA)
    outro = copy.deepcopy(alerta_ssh)
    outro["id"] = "1793270000.000002"

    alerta_analisado(client, auth, outro)

    sistema = _sistema_do_ultimo_pedido(gemini)
    assert "Decisões anteriores de analistas" in sistema
    assert NOTA in sistema
    assert "bloquear_ip" in sistema


def test_feedback_em_quarentena_nao_entra_no_prompt_ate_ser_liberado(client, auth, alerta_injecao, gemini):
    primeiro = alerta_analisado(client, auth, alerta_injecao)
    revisar(client, auth, primeiro, decisao="descartada", nota=NOTA)
    outro = copy.deepcopy(alerta_injecao)
    outro["id"] = "1793270000.000003"
    segundo = alerta_analisado(client, auth, outro)
    assert "Decisões anteriores" not in _sistema_do_ultimo_pedido(gemini)

    (item,) = feedbacks(client, auth)
    liberado = client.patch(f"/api/feedback/{item['id']}", headers=auth, json={"uso": "exemplo"})
    assert liberado.status_code == 200
    assert liberado.json()["motivo_uso"] == "Liberado por um analista."
    client.post(f"{URL}/{segundo}/analise", headers=auth, params={"refazer": True})

    assert NOTA in _sistema_do_ultimo_pedido(gemini)


def test_alterar_feedback_inexistente_retorna_404(client, auth):
    assert client.patch("/api/feedback/naoexiste", headers=auth, json={"uso": "exemplo"}).status_code == 404


def test_rotas_de_revisao_e_feedback_exigem_token(client):
    assert client.post(f"{URL}/1/revisao", json={"decisao": "aprovada"}).status_code == 401
    assert client.get("/api/feedback").status_code == 401


def test_listagem_traz_o_resumo_da_ultima_analise(client, auth, alerta_ssh, alerta_injecao, gemini):
    sem_analise = criar_alerta(client, auth, alerta_ssh)
    analisado = alerta_analisado(client, auth, alerta_injecao)
    revisar(client, auth, analisado, decisao="aprovada")

    por_id = {a["id"]: a for a in client.get(URL, headers=auth).json()}

    assert por_id[sem_analise]["analise"] is None
    resumo = por_id[analisado]["analise"]
    assert resumo["revisao"] == "aprovada"
    assert resumo["classificacao"] == SUGESTAO_PADRAO["classificacao"]
    assert resumo["indicios_manipulacao"] is True  # as políticas detectaram a injeção
