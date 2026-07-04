# opensmart/base - clean Debian 13 environment for the OpenSMART framework
FROM debian:13

LABEL org.opensmart.image="opensmart/base" \
      org.opensmart.description="Clean Debian 13 base for OpenSMART framework"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      wget \
      gnupg \
      lsb-release \
      procps \
      iproute2 \
      iputils-ping \
      net-tools \
      nano \
      less \
      tini \
 && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["bash"]
