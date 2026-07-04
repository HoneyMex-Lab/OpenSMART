# opensmart/zeek - Zeek network security monitor (tool only, no config)
# Zeek is not in Debian 13 repos; install from the official OpenSUSE OBS repo (Debian_13 build).
FROM opensmart/base

LABEL org.opensmart.image="opensmart/zeek"

ENV DEBIAN_FRONTEND=noninteractive

RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_13/ /' \
      > /etc/apt/sources.list.d/security:zeek.list \
 && curl -fsSL 'https://download.opensuse.org/repositories/security:/zeek/Debian_13/Release.key' \
      | gpg --dearmor > /etc/apt/trusted.gpg.d/security_zeek.gpg \
 && apt-get update \
 && apt-get install -y --no-install-recommends zeek \
 && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/zeek/bin:${PATH}"

# Tool only, no configuration. Keep the container alive as a ready-to-use Zeek host.
ENTRYPOINT ["bash"]
CMD ["-c", "zeek --version; echo 'Zeek installed - tool only, no config. Container idle.'; exec sleep infinity"]
