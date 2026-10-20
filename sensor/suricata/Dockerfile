# jasonish/suricata:8.0 - official community image (built from OISF source,
# AlmaLinux 9, includes suricata-update + suricatasc + Hyperscan).
# NOTE: `suricata/suricata` does NOT exist on Docker Hub - do not use.
ARG SURICATA_IMAGE=jasonish/suricata:8.0
FROM ${SURICATA_IMAGE}

USER root

# ethtool is not in the base image but our entrypoint uses it to disable
# GRO/LRO/TSO on the SPAN interface (bogus checksums / fragmented segments).
RUN dnf -y install ethtool \
    && dnf clean all

# Bake Emerging Threats open rules into the image at build time.
# Runtime rules live on the host mount ./sensor/suricata/rules - the entrypoint
# runs suricata-update there if the file is empty/missing.
# Refresh later with:  scripts/rule-update.sh  (suricata-update + live reload)
RUN suricata-update \
    || echo "WARN: rule download failed at build time; run scripts/rule-update.sh after deploy"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
