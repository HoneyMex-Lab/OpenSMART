# opensmart/suricata - Suricata IDS/IPS (rulesets fetched, configured for eth0)
FROM opensmart/base

LABEL org.opensmart.image="opensmart/suricata"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends suricata suricata-update jq \
 && rm -rf /var/lib/apt/lists/*

# Initial ruleset configuration: pull the default (ET Open) ruleset at build time.
RUN suricata-update update-sources \
 && suricata-update --no-test --no-reload || true

# Configure the capture interface to eth0 in the af-packet section.
RUN sed -i 's/^\(\s*\)- interface:.*/\1- interface: eth0/' /etc/suricata/suricata.yaml || true

# Run Suricata live on eth0, logging into the mounted /data volume.
ENTRYPOINT ["bash"]
CMD ["-c", "suricata --build-info >/dev/null 2>&1; mkdir -p /data/log; exec suricata -i eth0 -l /data/log -v"]
