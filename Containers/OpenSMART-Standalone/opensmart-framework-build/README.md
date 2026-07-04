# OpenSMART Framework — Build tree (docker-images)

Dockerfiles and helper scripts/templates for the custom OpenSMART images. The deploy tree
(compose stacks) lives in `../opensmart-framework`. See the bundle root `../README.md` and
`../MANIFEST.json` for the full picture.

## Build order

`opensmart/base` **must be built first** — every other image is `FROM opensmart/base`.

```bash
cd docker-images
docker build -t opensmart/base       ./base
docker build -t opensmart/zeek       ./zeek
docker build -t opensmart/suricata   ./suricata
docker build -t opensmart/openvpn    ./openvpn
docker build -t opensmart/wireguard  ./wireguard
```

## Images

| Image                 | Upstream source                              | Runtime behaviour |
|-----------------------|----------------------------------------------|-------------------|
| `opensmart/base`      | `debian:13` (official)                       | `ENTRYPOINT bash`; common tools (curl, iproute2, tini, …) |
| `opensmart/zeek`      | OpenSUSE OBS `security:zeek` Debian_13 repo  | Installs Zeek 8.2.0; **tool only**, container idles (`sleep infinity`) |
| `opensmart/suricata`  | Debian 13 repo + ET Open ruleset             | Pulls ET Open rules at build; runs `suricata -i eth0 -l /data/log` |
| `opensmart/openvpn`   | Debian 13 repo (openvpn, easy-rsa)           | Ships `gen-pki.sh` / `make-client.sh`; server **not** auto-started (no tun) |
| `opensmart/wireguard` | Debian 13 repo (wireguard-tools)             | `wg-up.sh` generates keys/config and brings `wg0` up |

## Helper files

### `openvpn/`
- **`Dockerfile`** — installs OpenVPN + easy-rsa, copies the scripts/templates into `/opt/opensmart`.
- **`gen-pki.sh`** — generates the PKI (EC `secp384r1` / SHA512): CA, server cert,
  `tls-crypt` key, CRL; writes the hardened `server.conf` and client template into `/data`.
  **Idempotent** — skips if `/data/pki/ca.crt` already exists.
- **`server.conf.tmpl`** — hardened server config (AES-256-GCM / CHACHA20-POLY1305,
  `tls-crypt`, `tls-version-min 1.2`, drops to `nobody:nogroup`, subnet `10.20.0.0/24`).
- **`client.ovpn.tmpl`** — client profile template; CA/cert/key/tls-crypt are inlined by
  `make-client.sh`.
- **`make-client.sh`** — `make-client.sh <client-name> [server-ip]` → issues a client cert
  and writes a self-contained `/data/clients/<name>.ovpn`.

### `wireguard/`
- **`Dockerfile`** — installs `wireguard-tools` + iptables; `ENTRYPOINT` is `wg-up.sh`.
- **`wg-up.sh`** — on first run generates the server keypair, `wg0.conf` (subnet
  `10.30.0.0/24`, port `51820`, NAT via `eth0`) and `client.conf.tmpl`, then `wg-quick up wg0`.

## Notes / environment constraints

- Zeek is intentionally **tool-only** (per the project spec) — no live capture is configured.
- Suricata and Arkime capture rely on host networking to see `eth0`.
- The OpenVPN server image is built and ready but the test LXC has **no `/dev/net/tun`**, so
  the server is only run manually once TUN is available (see `../README.md`).
- GeoIP/OUI enrichment files are **not** baked into the Arkime workflow; enable later via
  `/opt/arkime/bin/arkime_update_geo.sh` inside the capture container.
