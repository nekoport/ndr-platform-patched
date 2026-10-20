ARG ARKIME_VERSION=5.6.2
FROM ubuntu:24.04

ARG ARKIME_VERSION

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl iproute2 ethtool procps \
    && rm -rf /var/lib/apt/lists/*

# Install Arkime from the official GitHub release (amd64 deb for Ubuntu 24).
# Asset names include a distro+revision segment, e.g. for v5.6.2 the file is
#   arkime_5.6.2-1.ubuntu2404_amd64.deb   (NOT arkime_5.6.2.amd64.deb)
# If a future release uses a different revision (-2, -3, ...) or distro tag,
# override ARKIME_DEB with the exact asset filename listed at
# https://github.com/arkime/arkime/releases
ARG ARKIME_DEB=arkime_${ARKIME_VERSION}-1.ubuntu2404_amd64.deb

RUN curl -fsSL -o /tmp/arkime.deb \
      "https://github.com/arkime/arkime/releases/download/v${ARKIME_VERSION}/${ARKIME_DEB}" \
    && apt-get update \
    && apt-get install -y --no-install-recommends /tmp/arkime.deb \
    && rm /tmp/arkime.deb \
    && rm -rf /var/lib/apt/lists/*

COPY config.ini.template /opt/arkime/etc/config.ini.template
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /opt/arkime/raw

# capture needs raw socket; viewer serves the web UI
EXPOSE 8005

ENTRYPOINT ["/entrypoint.sh"]
