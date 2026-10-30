import json
import os
from pathlib import Path

# Tem que vir antes de importar o app: Settings exige API_TOKEN.
os.environ["API_TOKEN"] = "token-de-teste"

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import enriquecimento
from app.config import settings
from app.database import Base, get_db
from app.enriquecimento import get_http_client
from app.main import app
from falsos import RESPOSTA_ABUSEIPDB, RESPOSTA_VIRUSTOTAL, SUGESTAO_PADRAO, resposta_gemini

# Os testes nunca usam as chaves reais do .env; quem precisa liga chaves falsas.
settings.abuseipdb_api_key = None
settings.virustotal_api_key = None
settings.gemini_api_key = None

EXEMPLOS = Path(__file__).parent.parent / "exemplos"
HOSTS = {
    "api.abuseipdb.com": "abuseipdb",
    "www.virustotal.com": "virustotal",
    "generativelanguage.googleapis.com": "gemini",
}

# Banco em memória: cada teste começa vazio e nunca toca o alertas.db.
engine_teste = create_engine(
    "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
)
SessionTeste = sessionmaker(bind=engine_teste, autoflush=False)


def get_db_teste():
    db = SessionTeste()
    try:
        yield db
    finally:
        db.close()


def _sem_internet(requisicao: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("testes não acessam a internet", request=requisicao)


def get_http_client_teste():
    with httpx.Client(transport=httpx.MockTransport(_sem_internet)) as cliente:
        yield cliente


def _exemplo(nome: str) -> dict:
    return json.loads((EXEMPLOS / nome).read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def feedback_temporario(tmp_path, monkeypatch):
    """Cada teste escreve o feedback num arquivo próprio, nunca no dados/ real."""
    caminho = tmp_path / "feedback_ia.json"
    monkeypatch.setattr(settings, "feedback_arquivo", str(caminho))
    return caminho


@pytest.fixture
def client():
    Base.metadata.create_all(bind=engine_teste)
    app.dependency_overrides[get_db] = get_db_teste
    app.dependency_overrides[get_http_client] = get_http_client_teste
    yield TestClient(app)
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine_teste)


@pytest.fixture
def db():
    with SessionTeste() as sessao:
        yield sessao


@pytest.fixture
def auth():
    return {"Authorization": "Bearer token-de-teste"}


@pytest.fixture
def alerta_ssh():
    return _exemplo("alerta_ssh.json")


@pytest.fixture
def alerta_injecao():
    return _exemplo("alerta_injecao.json")


@pytest.fixture
def rede(client):
    """Faz o papel da internet (AbuseIPDB, VirusTotal e Gemini) e registra cada requisição.

    Para mudar a resposta de um serviço: rede["gemini"] = (codigo_http, corpo_json).
    """
    estado = {
        "chamadas": [],
        "abuseipdb": (200, RESPOSTA_ABUSEIPDB),
        "virustotal": (200, RESPOSTA_VIRUSTOTAL),
        "gemini": (200, resposta_gemini(SUGESTAO_PADRAO)),
    }

    def responder(requisicao: httpx.Request) -> httpx.Response:
        estado["chamadas"].append(requisicao)
        codigo, corpo = estado[HOSTS[requisicao.url.host]]
        return httpx.Response(codigo, json=corpo)

    def cliente_falso():
        with httpx.Client(transport=httpx.MockTransport(responder)) as cliente:
            yield cliente

    app.dependency_overrides[get_http_client] = cliente_falso
    return estado


@pytest.fixture
def fontes(rede, monkeypatch):
    """Liga a reputação com chaves falsas. Os IPs de documentação passam a contar como públicos."""
    monkeypatch.setattr(settings, "abuseipdb_api_key", SecretStr("chave-abuse-teste"))
    monkeypatch.setattr(settings, "virustotal_api_key", SecretStr("chave-vt-teste"))
    monkeypatch.setattr(enriquecimento, "ip_publico", lambda ip: True)
    return rede


@pytest.fixture
def gemini(rede, monkeypatch):
    """Liga a IA com uma chave falsa."""
    monkeypatch.setattr(settings, "gemini_api_key", SecretStr("chave-gemini-teste"))
    return rede
