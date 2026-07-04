#!/usr/bin/env bash
# Create a client certificate and emit a self-contained .ovpn into /data/clients/.
# Usage: make-client.sh <client-name> [server-ip-or-host]
set -euo pipefail

NAME="${1:?usage: make-client.sh <client-name> [server-ip-or-host]}"
SERVER_IP="${2:-SERVER_IP}"

PKI=/data/pki
EASY=/usr/share/easy-rsa/easyrsa
export EASYRSA_PKI="$PKI"
export EASYRSA_BATCH=1
export EASYRSA_ALGO=ec
export EASYRSA_CURVE=secp384r1
export EASYRSA_DIGEST=sha512

if [ ! -f "$PKI/issued/$NAME.crt" ]; then
  "$EASY" build-client-full "$NAME" nopass
fi

mkdir -p /data/clients
OUT="/data/clients/$NAME.ovpn"
{
  sed "s#__SERVER_IP__#$SERVER_IP#g" /data/client.ovpn.tmpl | grep -v '^#'
  echo "<ca>";        cat "$PKI/ca.crt";                 echo "</ca>"
  echo "<cert>";      openssl x509 -in "$PKI/issued/$NAME.crt"; echo "</cert>"
  echo "<key>";       cat "$PKI/private/$NAME.key";      echo "</key>"
  echo "<tls-crypt>"; cat "$PKI/ta.key";                 echo "</tls-crypt>"
} > "$OUT"

echo "Wrote $OUT"
