#!/usr/bin/env bash
# Generate WireGuard server keys + config + client template (in /data) and bring wg0 up.
set -euo pipefail

DATA=/data
WGCONF="$DATA/wg0.conf"
ADDR="10.30.0.1/24"
PORT="51820"
SERVER_IP="${SERVER_IP:-SERVER_IP}"

mkdir -p "$DATA"

# Server keypair (persisted in /data)
if [ ! -f "$DATA/server_private.key" ]; then
  umask 077
  wg genkey | tee "$DATA/server_private.key" | wg pubkey > "$DATA/server_public.key"
  echo "Generated WireGuard server keypair."
fi
PRIV="$(cat "$DATA/server_private.key")"
PUB="$(cat "$DATA/server_public.key")"

# Base server config (clients appended as [Peer] blocks)
if [ ! -f "$WGCONF" ]; then
  cat > "$WGCONF" <<EOF
[Interface]
Address = $ADDR
ListenPort = $PORT
PrivateKey = $PRIV
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Add client peers below, e.g.:
# [Peer]
# PublicKey = <client-public-key>
# AllowedIPs = 10.30.0.2/32
EOF
  echo "Created $WGCONF"
fi

# Client template
cat > "$DATA/client.conf.tmpl" <<EOF
[Interface]
PrivateKey = CLIENT_PRIVATE_KEY
Address = 10.30.0.X/32
DNS = 1.1.1.1

[Peer]
PublicKey = $PUB
Endpoint = $SERVER_IP:$PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

wg-quick down "$WGCONF" 2>/dev/null || true
wg-quick up "$WGCONF"
wg show
echo "WireGuard wg0 is up. Server public key: $PUB"
exec sleep infinity
