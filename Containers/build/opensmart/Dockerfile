FROM debian:13

LABEL org.opensmart.image=opensmart/web

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git nodejs npm python3 tini \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd opensmart -g 1000 \
    && useradd -u 1000 -g opensmart -s /bin/bash -m --home-dir /home/opensmart opensmart \
    && passwd -l opensmart \
    && passwd -l root

USER opensmart
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/home/opensmart/.local/bin:${PATH}"

WORKDIR /opt/opensmart
ENTRYPOINT ["tini", "--"]
CMD ["./opensmart.sh", "start", "--bind", "0.0.0.0:8000", "--prod"]
