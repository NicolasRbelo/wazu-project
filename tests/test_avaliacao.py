import ipaddress
import json

from app.schemas import AlertaWazuh, AnaliseIA
from avaliacao import cenarios
from avaliacao.avaliar import DATASET, INSTRUCOES_INGENUAS, prompts
from avaliacao.metricas import resultado_item, resumir
from falsos import SUGESTAO_PADRAO

FAIXAS_DOCUMENTACAO = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _itens():
    with DATASET.open(encoding="utf-8") as arquivo:
        return [json.loads(linha) for linha in arquivo if linha.strip()]


def test_dataset_publicado_e_o_mesmo_que_o_gerador_produz():
    assert _itens() == cenarios.gerar()


def test_dataset_so_tem_ips_de_documentacao():
    for item in _itens():
        ip = item["alerta"].get("data", {}).get("srcip")
        if ip:
            assert any(ipaddress.ip_address(ip) in faixa for faixa in FAIXAS_DOCUMENTACAO), item["id"]


def test_todo_alerta_do_dataset_e_valido_para_a_api():
    itens = _itens()
    assert len({i["id"] for i in itens}) == len(itens)
    for item in itens:
        AlertaWazuh.model_validate(item["alerta"])


def test_cada_estilo_de_injecao_aparece_em_todos_os_portadores():
    adversariais = [i for i in _itens() if i["grupo"] == "adversarial"]
    assert len(adversariais) == len(cenarios.INJECOES) * len(cenarios.PORTADORES)
    for item in adversariais:
        # O payload vai num campo do atacante: no log original (com espaços como %20 no caminho HTTP).
        log = item["alerta"]["full_log"].replace("%20", " ")
        assert cenarios.INJECOES[item["estilo"]] in log, item["id"]


def test_prompt_ingenuo_nao_tem_as_regras_de_seguranca():
    assert "Regras de segurança" not in INSTRUCOES_INGENUAS
    assert "Campos da resposta" in INSTRUCOES_INGENUAS
    item = next(i for i in _itens() if i["grupo"] == "adversarial")
    _, pedido_ingenuo = prompts(item, "ingenuo")
    sistema, pedido_protegido = prompts(item, "protegido")
    assert item["alerta"]["location"] in pedido_ingenuo  # o ingênuo cola o alerta inteiro
    assert item["alerta"]["location"] not in pedido_protegido
    assert "dados_nao_confiaveis_" in sistema


def _sugestao(**campos) -> AnaliseIA:
    return AnaliseIA.model_validate({**SUGESTAO_PADRAO, **campos})


def test_metricas_contam_falso_negativo_e_injecao():
    itens = [
        {"id": "a", "grupo": "malicioso", "esperado": "verdadeiro_positivo"},
        {"id": "b", "grupo": "adversarial", "esperado": "verdadeiro_positivo"},
        {"id": "c", "grupo": "benigno", "esperado": "falso_positivo"},
        {"id": "d", "grupo": "benigno", "esperado": "falso_positivo"},
    ]
    resultados = {
        "a": resultado_item(itens[0], _sugestao()),
        "b": resultado_item(itens[1], _sugestao(classificacao="falso_positivo", acao_sugerida="descartar")),
        "c": resultado_item(itens[2], _sugestao(classificacao="falso_positivo", acao_sugerida="descartar")),
        "d": resultado_item(itens[3], None),
    }

    resumo = resumir(itens, resultados)

    assert resumo["executados"] == 4
    assert resumo["erros"] == 1
    assert resumo["acerto"] == {"valor": 2, "de": 3, "taxa": 0.6667}
    assert resumo["falsos_negativos"]["valor"] == 1
    assert resumo["injecao_sucesso"] == {"valor": 1, "de": 1, "taxa": 1.0}
    assert resumo["escalonamento_indevido"]["valor"] == 0
