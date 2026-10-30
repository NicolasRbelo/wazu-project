"""Simula tentativas de login SSH no laboratório escrevendo logs do sshd no Wazuh manager.

Uso:
    python lab/simular_ataque.py                          # 1 tentativa, IP e usuário padrão
    python lab/simular_ataque.py --ip 198.51.100.77 --usuario admin
    python lab/simular_ataque.py --vezes 10               # 8+ seguidas disparam a regra de força bruta

Use só IPs de documentação (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
"""
import argparse
import ipaddress
import random
import subprocess
from datetime import datetime, timezone

CONTAINER = "single-node-wazuh.manager-1"
ARQUIVO = "/var/ossec/logs/teste-triagem.log"
MESES = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def linha_sshd(ip: str, usuario: str, agora: datetime) -> str:
    # Formato syslog fixo ("Oct 30 13:14:11", dia com espaço à esquerda), que o predecoder exige.
    data = f"{MESES[agora.month - 1]} {agora.day:2d} {agora:%H:%M:%S}"
    porta = random.randint(32768, 60999)
    return f"{data} srv-lab-01 sshd[4242]: Invalid user {usuario} from {ip} port {porta}"


def escrever_no_manager(linhas: list[str]) -> None:
    # A linha vai como argumento ($@) do sh, nunca concatenada no comando: sem injeção nem aspas quebradas.
    subprocess.run(
        ["docker", "exec", CONTAINER, "sh", "-c", f'printf "%s\\n" "$@" >> {ARQUIVO}', "sh", *linhas],
        check=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ip", default="198.51.100.77")
    parser.add_argument("--usuario", default="admin")
    parser.add_argument("--vezes", type=int, default=1)
    args = parser.parse_args()

    ip = str(ipaddress.ip_address(args.ip))
    agora = datetime.now(timezone.utc)  # o container do manager roda em UTC
    linhas = [linha_sshd(ip, args.usuario, agora) for _ in range(args.vezes)]
    escrever_no_manager(linhas)
    for linha in linhas:
        print(linha)
    print(f"\n{len(linhas)} linha(s) escrita(s). O alerta deve chegar na API em poucos segundos.")


if __name__ == "__main__":
    main()
