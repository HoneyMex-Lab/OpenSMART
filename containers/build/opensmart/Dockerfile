FROM debian:13

LABEL org.opensmart.image=opensmart/web

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git nodejs npm python3 tini gnupg \
    && rm -rf /var/lib/apt/lists/*

# Docker CLI + compose plugin, used by the backend's container-provisioning
# module to run `docker compose` against the docker-socket-proxy sidecar
# (DOCKER_HOST is set in docker-compose.yml) — no docker.sock is mounted here.
RUN install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd opensmart -g 1000 \
    && useradd -u 1000 -g opensmart -s /bin/bash -m --home-dir /home/opensmart opensmart \
    && passwd -l opensmart \
    && passwd -l root

USER opensmart
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/home/opensmart/.local/bin:${PATH}"

# No fixed WORKDIR: this image is only ever run via
# containers/run/opensmart/docker-compose.yml, which sets `working_dir` to
# wherever the project actually lives on the host (host-path parity) so
# sibling-container bind mounts under containers/run/ resolve correctly.
ENTRYPOINT ["tini", "--"]
CMD ["./opensmart.sh", "start", "--bind", "0.0.0.0:8000", "--prod"]
