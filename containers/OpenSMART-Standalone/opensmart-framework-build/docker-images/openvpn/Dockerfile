# opensmart/openvpn - OpenVPN server with hardened config + PKI/client tooling.
# NOTE: The container is NOT auto-started in this environment because the LXC host
# has no /dev/net/tun. PKI/cert/config artifacts are generated into the mounted /data.
FROM opensmart/base

LABEL org.opensmart.image="opensmart/openvpn"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends openvpn easy-rsa openssl \
 && rm -rf /var/lib/apt/lists/*

COPY gen-pki.sh server.conf.tmpl client.ovpn.tmpl make-client.sh /opt/opensmart/
RUN chmod +x /opt/opensmart/gen-pki.sh /opt/opensmart/make-client.sh

ENTRYPOINT ["bash"]
CMD ["-c", "echo 'OpenSMART OpenVPN image.'; echo 'Generate PKI:  /opt/opensmart/gen-pki.sh'; echo 'Make client:   /opt/opensmart/make-client.sh <name> <server_ip>'; echo 'Start server (needs /dev/net/tun): openvpn --config /data/server.conf'; exec sleep infinity"]
