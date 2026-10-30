# Integração Wazuh → wazuh-triagem

`custom-wazuh-triagem.py` é chamado pelo `wazuh-integratord` a cada alerta que
passa no filtro do bloco `<integration>` e faz um `POST /api/alertas` com o
token Bearer.

## Instalação no Wazuh manager (testado no 4.14.9)

O integratord executa `/var/ossec/integrations/<name>`. No 4.14 cada integração
é um wrapper em shell sem extensão que roda `<name>.py` com o Python embutido;
o wrapper do `slack` é genérico e serve para o nosso.

```bash
cp custom-wazuh-triagem.py /var/ossec/integrations/
cd /var/ossec/integrations
cp slack custom-wazuh-triagem
chown root:wazuh custom-wazuh-triagem custom-wazuh-triagem.py
chmod 750 custom-wazuh-triagem custom-wazuh-triagem.py
```

Em `/var/ossec/etc/ossec.conf`, dentro de `<ossec_config>`:

```xml
<integration>
  <name>custom-wazuh-triagem</name>
  <hook_url>http://192.0.2.20:8000/api/alertas</hook_url>
  <api_key>MESMO_VALOR_DO_API_TOKEN_DO_.env</api_key>
  <level>5</level>
  <alert_format>json</alert_format>
</integration>
```

- `<name>` é o nome do wrapper, **sem** `.py`, e precisa começar com `custom-`.
- `<alert_format>json</alert_format>` é obrigatório: o script lê JSON.
- `<level>` filtra quais alertas são enviados (aqui, nível 5 ou mais).
- Fora do laboratório, use `https` no `hook_url`: o token vai no header.

Depois: `systemctl restart wazuh-manager`. Erros do script aparecem em
`/var/ossec/logs/integrations.log`; erros do integratord, em
`/var/ossec/logs/ossec.log`.

A API precisa escutar num IP que o manager alcance: ajuste `API_HOST` no `.env`.

## Wazuh em Docker (wazuh-docker single-node, Docker Desktop no Windows)

- `hook_url`: `http://host.docker.internal:8000/api/alertas`. Funciona com a API
  escutando só em `127.0.0.1`, porque o Docker Desktop encaminha para o host.
- `/var/ossec/integrations` é um volume: copie os arquivos com `docker cp` e ajuste
  dono e permissão com `docker exec`, como acima. Eles sobrevivem a reinícios.
- Edite `config/wazuh_cluster/wazuh_manager.conf`, no clone do wazuh-docker. O
  container só copia esse arquivo para `/var/ossec/etc/ossec.conf` na criação, e um
  `docker compose restart` **não** recopia. Com o container já criado, copie à mão e
  reinicie os serviços:

  ```bash
  docker exec single-node-wazuh.manager-1 cp /wazuh-config-mount/etc/ossec.conf /var/ossec/etc/ossec.conf
  docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
  ```

- Se aparecer `wazuh-integratord: INFO: Remote integrations not configured` no
  `ossec.log`, o bloco `<integration>` não chegou ao `ossec.conf` em uso.

## Simular um ataque no laboratório

Acrescente ao `ossec.conf` um `<localfile>` em formato `syslog` apontando para
`/var/ossec/logs/teste-triagem.log` e escreva linhas do sshd nesse arquivo com
`lab/simular_ataque.py`, a partir da raiz do projeto:

```powershell
python lab/simular_ataque.py --ip 198.51.100.77 --usuario admin
python lab/simular_ataque.py --vezes 10     # força bruta: 8+ seguidas disparam a regra 5712 (nível 10)
```

Não use `docker exec ... sh -c '... "..." ...'` direto no PowerShell 5.1: ele remove
as aspas duplas internas e o `sh` recebe o comando quebrado.

A regra 5710 (nível 5) dispara em cerca de 2 segundos e o alerta aparece em
`GET /api/alertas`.

## Teste manual sem Wazuh

Com a API rodando (`python run.py`):

```powershell
python integrations/custom-wazuh-triagem.py exemplos/alerta_ssh.json SEU_TOKEN http://127.0.0.1:8000/api/alertas
```

Código de saída 0 = enviado (ou já existia).
