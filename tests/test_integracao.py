import importlib.util
import io
import json
import urllib.error
from pathlib import Path

import pytest

# O nome do arquivo tem hífen (exigência do Wazuh), então não dá para usar import normal.
CAMINHO = Path(__file__).parent.parent / "integrations" / "custom-wazuh-triagem.py"
spec = importlib.util.spec_from_file_location("integracao", CAMINHO)
integracao = importlib.util.module_from_spec(spec)
spec.loader.exec_module(integracao)

URL = "http://127.0.0.1:8000/api/alertas"


class RespostaFalsa:
    status = 201

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


@pytest.fixture
def arquivo_alerta(tmp_path, alerta_ssh):
    caminho = tmp_path / "alerta.json"
    caminho.write_text(json.dumps(alerta_ssh), encoding="utf-8")
    return str(caminho)


@pytest.fixture
def log(tmp_path, monkeypatch):
    caminho = tmp_path / "integrations.log"
    monkeypatch.setattr(integracao, "LOG", caminho)
    return caminho


@pytest.fixture
def enviadas(monkeypatch):
    requisicoes = []

    def urlopen_falso(requisicao, timeout):
        requisicoes.append(requisicao)
        return RespostaFalsa()

    monkeypatch.setattr(integracao.urllib.request, "urlopen", urlopen_falso)
    return requisicoes


def test_envia_alerta_com_token(arquivo_alerta, alerta_ssh, log, enviadas):
    codigo = integracao.main(["script", arquivo_alerta, "token-x", URL])

    assert codigo == 0
    assert len(enviadas) == 1
    requisicao = enviadas[0]
    assert requisicao.full_url == URL
    assert requisicao.get_method() == "POST"
    assert requisicao.get_header("Authorization") == "Bearer token-x"
    assert json.loads(requisicao.data) == alerta_ssh


def test_erro_http_registra_sem_vazar_token(arquivo_alerta, log, monkeypatch):
    def urlopen_401(requisicao, timeout):
        raise urllib.error.HTTPError(URL, 401, "Unauthorized", {}, io.BytesIO())

    monkeypatch.setattr(integracao.urllib.request, "urlopen", urlopen_401)

    codigo = integracao.main(["script", arquivo_alerta, "token-secreto", URL])

    assert codigo == 1
    conteudo = log.read_text(encoding="utf-8")
    assert "401" in conteudo
    assert "token-secreto" not in conteudo


def test_hook_url_que_nao_e_http_e_recusado(arquivo_alerta, log, enviadas):
    codigo = integracao.main(["script", arquivo_alerta, "token-x", "file:///etc/passwd"])

    assert codigo == 1
    assert enviadas == []


def test_argumentos_faltando(log, enviadas):
    assert integracao.main(["script"]) == 1
    assert enviadas == []
