#!/usr/bin/env python3
"""Integração customizada do Wazuh: envia cada alerta para a API do wazuh-triagem.

O wazuh-integratord chama este script com:
    argv[1]  arquivo temporário com o alerta em JSON
    argv[2]  <api_key> do bloco <integration> (o API_TOKEN da API)
    argv[3]  <hook_url> do bloco <integration> (ex.: http://192.0.2.20:8000/api/alertas)

Só usa a biblioteca padrão, para rodar tanto no Python embutido do Wazuh
quanto no python3 do sistema.
"""
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

LOG = Path("/var/ossec/logs/integrations.log")
TIMEOUT = 10


def registrar(mensagem: str) -> None:
    linha = f"{datetime.now(timezone.utc).isoformat()} custom-wazuh-triagem: {mensagem}\n"
    try:
        with LOG.open("a", encoding="utf-8") as arquivo:
            arquivo.write(linha)
    except OSError:
        sys.stderr.write(linha)


def ler_alerta(caminho: str) -> dict:
    with open(caminho, encoding="utf-8") as arquivo:
        return json.load(arquivo)


def enviar_alerta(alerta: dict, token: str, url: str) -> int:
    # Sem esta checagem, um hook_url "file://..." faria o urllib ler arquivos locais.
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise ValueError(f"hook_url precisa ser http ou https: {url!r}")

    requisicao = urllib.request.Request(
        url,
        data=json.dumps(alerta).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(requisicao, timeout=TIMEOUT) as resposta:
        return resposta.status


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        registrar("uso: custom-wazuh-triagem.py <arquivo_alerta> <api_key> <hook_url>")
        return 1
    caminho, token, url = argv[1], argv[2], argv[3]

    try:
        alerta = ler_alerta(caminho)
        enviar_alerta(alerta, token, url)
    except urllib.error.HTTPError as erro:
        # Nunca registrar o token: só o status e o id do alerta.
        registrar(f"API respondeu {erro.code} ao alerta {alerta.get('id')}")
        return 1
    except (urllib.error.URLError, OSError, ValueError) as erro:
        registrar(f"falha ao enviar alerta: {erro}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
