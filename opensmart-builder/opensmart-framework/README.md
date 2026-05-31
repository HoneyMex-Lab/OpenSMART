# OpenSMART Framework — Template (deploy tree)

Network security monitoring stack, container-based, on Debian 13 + Docker.
This is the **deploy tree**; the image **build tree** lives in `../opensmart-framework-build`.
For the full guide and a machine-readable description, see the bundle root
(`../README.md` and `../MANIFEST.json`).

## Layout
```
opensmart-framework/containers/<svc>/docker-compose.yml + volumes/data
opensmart-framework-build/docker-images/<img>/Dockerfile   (build context)
```

## Images (built from opensmart-framework-build/docker-images)
| Image              | Base           | Notes                                            |
|--------------------|----------------|--------------------------------------------------|
| opensmart/base     | debian:13      | Clean base, ENTRYPOINT bash                      |
| opensmart/zeek     | opensmart/base | Zeek 8.2.0 (OBS Debian_13 repo), tool only, no config |
| opensmart/suricata | opensmart/base | Suricata 7.0.10 + ET Open rules, libpcap on eth0 |
| opensmart/openvpn  | opensmart/base | CA/server cert/client template, hardened config  |
| opensmart/wireguard| opensmart/base | wireguard-tools, server keys + client template   |

Official images used directly: `opensearchproject/opensearch:2.18.0`,
`ghcr.io/arkime/arkime/arkime:v6-latest`, `nginx:1.27`.

## Networking
- **Host network**: zeek, suricata, arkime-capture (need to sniff eth0).
- **opensmart** (external bridge, 172.250.250.0/24): opensearch, arkime-viewer,
  openvpn (defined), wireguard, nginx.

## Volumes
Every service mounts `./volumes/data` → `/data`.

## Ports (published on host)
- OpenSearch 9200, Arkime viewer 8005, nginx 8080, WireGuard 51820/udp,
  OpenVPN 1194/udp (only when manually enabled).

## Deploy
```
SERVER_IP=<host-ip> ./deploy.sh
```
Or per-stack: `cd containers/<svc> && docker compose up -d`.

## Credentials (defaults — change before real use)
- **Arkime viewer** `http://<host>:8005` — user **admin** / password **changeme**
  (digest auth, admin role). Created by `deploy.sh`. Rotate with:
  `docker exec opensmart-arkime-viewer /opt/arkime/bin/arkime_add_user.sh admin "Admin User" <NEW> --admin`
- **OpenSearch** `http://<host>:9200` — **no authentication** (security plugin disabled).
- **OpenVPN / WireGuard** — key/certificate based, no passwords.

See `../README.md` → *Credentials & Defaults* for the full list.

## Tuning (8GB / 6 vCPU host)
- OpenSearch heap `-Xms2g -Xmx2g`.
- Arkime `packetThreads=2`, `pcapBufferSize=33554432` (32MB), `pcapReadMethod=libpcap`,
  `snapLen=32768`.

## Caveats in this environment
- **OpenVPN is NOT started** — the LXC host has no `/dev/net/tun`. PKI/cert/config are
  generated into `containers/openvpn/volumes/data`. To run it, enable TUN on the Proxmox
  host, add `devices: ["/dev/net/tun:/dev/net/tun"]` to the compose, then
  `docker compose --profile manual up -d`.
- **OpenSearch security disabled**; `bootstrap.memory_lock=false` (LXC `memlock`=8192).
- **Arkime uses libpcap** (not afpacketv3) because the LXC `memlock` cap blocks the
  tpacketv3 ring mmap. Capture (host net) and viewer (opensmart) share node name
  `opensmart` and the same `/data/raw` pcap dir.
