#!/usr/bin/env bash
# Generate the OpenVPN PKI (CA + server cert + tls-crypt key + CRL) and the
# hardened server.conf and client template into the mounted /data volume.
set -euo pipefail

DATA=/data
PKI="$DATA/pki"
EASY=/usr/share/easy-rsa/easyrsa

export EASYRSA_PKI="$PKI"
export EASYRSA_BATCH=1
export EASYRSA_ALGO=ec
export EASYRSA_CURVE=secp384r1
export EASYRSA_DIGEST=sha512
export EASYRSA_CERT_EXPIRE=3650
export EASYRSA_CA_EXPIRE=3650

mkdir -p "$DATA/log"

if [ -f "$PKI/ca.crt" ]; then
  echo "PKI already exists at $PKI - skipping generation."
else
  "$EASY" init-pki
  "$EASY" --req-cn="OpenSMART-VPN-CA" build-ca nopass
  "$EASY" build-server-full server nopass
  "$EASY" gen-crl
  openvpn --genkey secret "$PKI/ta.key"     # tls-crypt key
  chmod 600 "$PKI/ta.key"
  echo "PKI generated."
fi

# Hardened server config
sed "s#__PKI__#$PKI#g" /opt/opensmart/server.conf.tmpl > "$DATA/server.conf"

# Client template + helper script
cp /opt/opensmart/client.ovpn.tmpl "$DATA/client.ovpn.tmpl"
cp /opt/opensmart/make-client.sh   "$DATA/make-client.sh"
chmod +x "$DATA/make-client.sh"

echo "Done. Artifacts in $DATA:"
echo "  - pki/ca.crt, pki/issued/server.crt, pki/private/server.key, pki/ta.key, pki/crl.pem"
echo "  - server.conf (hardened)"
echo "  - client.ovpn.tmpl, make-client.sh"
