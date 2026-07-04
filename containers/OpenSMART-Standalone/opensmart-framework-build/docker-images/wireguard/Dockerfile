# opensmart/wireguard - WireGuard server (keys + base config + client template)
FROM opensmart/base

LABEL org.opensmart.image="opensmart/wireguard"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends wireguard-tools iptables openresolv \
 && rm -rf /var/lib/apt/lists/*

COPY wg-up.sh /opt/opensmart/wg-up.sh
RUN chmod +x /opt/opensmart/wg-up.sh

ENTRYPOINT ["/opt/opensmart/wg-up.sh"]
