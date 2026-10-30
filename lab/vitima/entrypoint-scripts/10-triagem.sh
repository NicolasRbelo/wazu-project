#!/bin/bash
# Roda antes do agente iniciar: manda o agente ler o auth log e o access log do nginx.
CONF=/var/ossec/etc/ossec.conf

mkdir -p /var/log/nginx
touch /var/log/secure /var/log/messages /var/log/nginx/access.log

if ! grep -q "/var/log/secure" "$CONF"; then
  # Só o último </ossec_config> do arquivo recebe os blocos.
  sed -i '$ s#</ossec_config>#  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/secure</location>\n  </localfile>\n\n  <localfile>\n    <log_format>apache</log_format>\n    <location>/var/log/nginx/access.log</location>\n  </localfile>\n</ossec_config>#' "$CONF"
fi
