# NDR local.zeek - Phase 0-2 telemetry set
# Loads only the protocol logs the pipeline ingests (conn, dns, http, tls)
# to keep disk and CPU under the 8-core sizing budget.
#
# v0.12.5: tuned for zeek/zeek:lts (Zeek 9.x), validated on the real VM
# deploy (10.0.106.232). Zeek 9 removed several knobs this file used:
#   * @load base/protocols/weird  - module gone in 9.0.0 (deploy FATAL).
#     weird.log is not ingested by the pipeline default set anyway.
#   * redef Log::default_scope    - removed upstream (deploy FATAL).
#   * redef AfPacket::snaplen / AfPacket::buffer_size - removed upstream
#     (deploy FATAL). Ring tuning now lives in the af_packet plugin
#     defaults; pin an older ZEEK_IMAGE in .env if you need them back:
#       redef Log::default_scope = "ndr";
#       redef AfPacket::snaplen = 0;                      # full packet
#       redef AfPacket::buffer_size = 256 * 1024 * 1024;  # 256 MB ring

@load base/init-default.zeek
@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/ssh

# ---- JSON output -------------------------------------------------
@load policy/tuning/json-logs.zeek
redef LogAscii::use_json = T;

# ---- Volume control ----------------------------------------------
# Rotation/archive is handled by `zeekctl cron` (entrypoint loop).
redef Log::default_rotation_interval = 1hr;

# TLS: keep certificate metadata (subject/issuer in ssl.log).
# Do NOT extract cert PEM or file content to disk - PCAP is the evidence store.

# Optional extras (uncomment and redeploy if needed):
# @load policy/protocols/conn/known-hosts
# @load policy/protocols/conn/vlan-logging
# @load policy/misc/detect-traceroute

# Notices stay in notice.log - no email relay inside the sensor VM.
redef Notice::mail_dest = "";
