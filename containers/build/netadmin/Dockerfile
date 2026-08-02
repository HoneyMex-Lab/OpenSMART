# opensmart/netadmin - nftables + inspection tools for the Firewall module's
# one-off, host-networked containers (see backend/app/hostnet.py,
# backend/app/firewall.py). Never runs long-lived; the kernel enforces the
# ruleset once applied, this image just renders/validates/applies it.
FROM opensmart/base

LABEL org.opensmart.image="opensmart/netadmin"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends nftables jq conntrack iptables \
 && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["bash"]
