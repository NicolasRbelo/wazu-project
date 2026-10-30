# Atacante do laboratório: ferramentas reais (hydra, curl, ssh) contra a vítima.
FROM alpine:3.20

RUN apk add --no-cache bash hydra curl openssh-client

COPY ataque usuarios.txt senhas.txt /opt/ataque/
RUN chmod +x /opt/ataque/ataque && ln -s /opt/ataque/ataque /usr/local/bin/ataque

CMD ["sleep", "infinity"]
