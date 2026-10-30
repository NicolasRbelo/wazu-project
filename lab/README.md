# Laboratório de ataque

Uma **vítima** monitorada por um agente Wazuh e um **atacante** com ferramentas reais. Os ataques geram alertas de verdade, que passam pela integração até a API de triagem.

| Container | O que roda |
|---|---|
| `vitima` | Agente Wazuh 4.14.9 (imagem oficial), OpenSSH, nginx e rsyslog. O agente lê `/var/log/secure` e o access log do nginx. |
| `atacante` | Alpine com hydra, curl e o cliente ssh. O script `ataque` traz os cenários. |

## Pré-requisitos

1. O Wazuh single-node do [wazuh-docker](https://github.com/wazuh/wazuh-docker) rodando. Os dois containers entram na rede dele (`single-node_default`).
2. A integração instalada no manager ([integrations/README.md](../integrations/README.md)).
3. A API rodando (`python run.py`).

## Subir

```powershell
docker compose -f lab/docker-compose.yml up -d --build
```

O agente se registra sozinho como `vitima-lab`. Para conferir:

```powershell
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

## Regra de detecção de prompt injection

[wazuh/triagem_ia_rules.xml](wazuh/triagem_ia_rules.xml) transforma a própria tentativa de enganar a IA em alerta de nível 10:
- **100210:** nome de usuário SSH com instrução para a IA;
- **100211:** URL ou User-Agent com instrução, inclusive codificada na URL.

```powershell
docker cp lab/wazuh/triagem_ia_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/triagem_ia_rules.xml
docker exec single-node-wazuh.manager-1 sh -c "chown wazuh:wazuh /var/ossec/etc/rules/triagem_ia_rules.xml && /var/ossec/bin/wazuh-control restart"
```

## Atacar

```powershell
docker compose -f lab/docker-compose.yml exec atacante ataque forca-bruta     # hydra contra o SSH
docker compose -f lab/docker-compose.yml exec atacante ataque varredura-web   # caminhos sensíveis com User-Agent de scanner
docker compose -f lab/docker-compose.yml exec atacante ataque sqli            # SQL injection na URL
docker compose -f lab/docker-compose.yml exec atacante ataque injecao         # prompt injection no usuário SSH e no User-Agent
docker compose -f lab/docker-compose.yml exec atacante ataque tudo
```

Uma rodada de `ataque tudo`, medida aqui, gerou **291 alertas** da vítima, que a API agrupou em **4 incidentes**: 185 do IP atacante, 93 da varredura de conformidade CIS do próprio agente, e outros 2. Regras disparadas:
- força bruta: 5712, 5763 e 99× 5710;
- User-Agent de scanner: 31508;
- SQL injection: 31103;
- as duas regras de prompt injection: 100210 e 100211.

## Resposta ativa (bloqueio com aprovação)

Com `WAZUH_API_*` no `.env` (veja o `.env.example`), um alerta que o analista decidiu como "bloquear IP" ganha, no painel, o botão de bloqueio com confirmação. A API chama `PUT /active-response` com `!firewall-drop`, e a vítima ganha uma regra `iptables -A INPUT -s <ip> -j DROP`. O atacante deixa de alcançá-la.

O bloqueio dura até ser removido. Para desfazer no laboratório:

```powershell
docker exec wazuh-triagem-lab-vitima-1 iptables -D INPUT -s <ip>/32 -j DROP
```

## Desligar

```powershell
docker compose -f lab/docker-compose.yml down
```

Os containers não guardam estado próprio. Para remover o agente do manager também, use `manage_agents -r <id>` no manager.
