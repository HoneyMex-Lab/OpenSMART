#!/usr/bin/env bash
# Deploy the OpenSMART framework stacks (idempotent).
# Run from the framework root (the dir containing containers/).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
SERVER_IP="${SERVER_IP:-$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')}"
export SERVER_IP
ES_URL="http://localhost:9200"
ARKIME_IMG="ghcr.io/arkime/arkime/arkime:v6-latest"

echo "==> Ensuring opensmart network exists"
docker network inspect opensmart >/dev/null 2>&1 || \
  docker network create --driver bridge --subnet 172.250.250.0/24 opensmart

echo "==> Preparing volume permissions"
mkdir -p containers/opensearch/volumes/data containers/arkime/volumes/data/raw
chown -R 1000:1000 containers/opensearch/volumes/data || true
chmod -R 0777 containers/arkime/volumes/data || true

echo "==> OpenSearch"
( cd containers/opensearch && docker compose up -d )
echo -n "   waiting for OpenSearch "
for i in $(seq 1 60); do
  if curl -fs "$ES_URL/_cluster/health" >/dev/null 2>&1; then echo " up"; break; fi
  echo -n "."; sleep 3
done

echo "==> Arkime capture + viewer (capture runs 'db.pl init --ifneeded' via docker.sh)"
( cd containers/arkime && docker compose up -d )

echo -n "   waiting for Arkime DB init (arkime_users index) "
for i in $(seq 1 60); do
  if curl -fs "$ES_URL/_cat/indices/arkime_users" 2>/dev/null | grep -q arkime_users; then echo " ready"; break; fi
  echo -n "."; sleep 5
done

echo "==> Ensuring Arkime admin user (admin/changeme)"
docker exec opensmart-arkime-viewer \
  /opt/arkime/bin/arkime_add_user.sh admin "Admin User" changeme --admin 2>/dev/null || \
  echo "   (could not add admin yet; re-run once viewer is healthy)"

echo "==> Suricata"
( cd containers/suricata && docker compose up -d )

echo "==> Zeek"
( cd containers/zeek && docker compose up -d )

echo "==> WireGuard"
( cd containers/wireguard && docker compose up -d )

echo "==> nginx"
( cd containers/nginx && docker compose up -d )

echo "==> OpenVPN PKI generation (server NOT started - no /dev/net/tun)"
( cd containers/openvpn && docker compose run --rm openvpn /opt/opensmart/gen-pki.sh ) || true

echo "==> Done. Running containers:"
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
