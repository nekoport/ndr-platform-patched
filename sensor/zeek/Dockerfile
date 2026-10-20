ARG ZEEK_IMAGE=zeek/zeek:lts
FROM ${ZEEK_IMAGE}
# ':lts' MOVED under our feet once already (7/8 -> 9.x broke local.zeek
# and the entrypoint in the first real VM deploy - v0.12.4 finding).
# local.zeek + entrypoint are now Zeek-9-compatible, but for
# reproducibility pin the image in .env:  ZEEK_IMAGE=zeek/zeek:9.0.0

# Templates are rendered by the entrypoint (interface name comes from env)
USER root
# entrypoint needs ip/ethtool (iface up + promisc + offload off); the
# official Zeek image ships neither.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 ethtool \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /templates
COPY node.cfg.tmpl /templates/node.cfg.tmpl
COPY entrypoint.sh /entrypoint.sh
COPY local.zeek /usr/local/zeek/share/zeek/site/local.zeek
# Custom Zeek scripts are NOT copied by default (0.12.3 shipped a
# `COPY scripts/` for a directory that does not exist, which broke the
# whole sensor build). To add custom scripts later:
#   1. create sensor/zeek/scripts/ with your .zeek files
#   2. re-add:  COPY scripts/ /usr/local/zeek/share/zeek/site/custom/
#   3. @load them from local.zeek
RUN chmod +x /entrypoint.sh \
    && mkdir -p /usr/local/zeek/logs

# The official image ships af_packet plugin enabled; verify at first deploy:
#   docker exec ndr-zeek zeek -N AfPacket
ENTRYPOINT ["/entrypoint.sh"]
