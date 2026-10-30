# Vítima do laboratório: o agente oficial do Wazuh com um SSH e um nginx expostos na rede do lab.
FROM wazuh/wazuh-agent:4.14.9

RUN dnf install -y openssh-server nginx rsyslog iptables-nft procps-ng \
    && dnf clean all \
    && ssh-keygen -A \
    # Usuário real, com senha aleatória gerada no build e nunca exibida: a força bruta não acerta.
    && useradd -m analista \
    && echo "analista:$(head -c 32 /dev/urandom | base64)" | chpasswd \
    # Formato combined, que o decoder de access log do Wazuh lê.
    && sed -i 's#access_log  /var/log/nginx/access.log  main;#access_log  /var/log/nginx/access.log  combined;#' /etc/nginx/nginx.conf

COPY rsyslog.conf /etc/rsyslog.conf
COPY sshd-lab.conf /etc/ssh/sshd_config.d/10-lab.conf
COPY services.d/ /etc/services.d/
COPY entrypoint-scripts/ /entrypoint-scripts/
RUN chmod +x /etc/services.d/*/run /entrypoint-scripts/*.sh

EXPOSE 22 80
