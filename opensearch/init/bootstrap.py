#!/usr/bin/env python3
"""
NDR OpenSearch bootstrap (Phase 0-2).

Creates, idempotently:
  * ISM retention policy (delete indices older than RETENTION_DAYS)
  * Composable index templates with explicit mappings for:
      ndr-zeek-conn-* / ndr-zeek-dns-* / ndr-zeek-http-* / ndr-zeek-tls-*
      ndr-suricata-* / ndr-alerts-* / ndr-health-* / ndr-ioc-matches-*
  * Read aliases (ndr-events-read, ndr-alerts-read, ndr-health-read,
    ndr-ioc-matches-read)
  * Initial bootstrap indices so aliases resolve before first ingest

Stdlib only (urllib) so it can run in a bare python:3.12-slim container.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

OS_URL = os.environ.get("OS_URL", "http://opensearch:9200").rstrip("/")
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "60"))
HEALTH_RETENTION_DAYS = int(os.environ.get("HEALTH_RETENTION_DAYS", "14"))
IOC_RETENTION_DAYS = int(os.environ.get("IOC_RETENTION_DAYS", "90"))
POLICY_ID = "ndr-retention"


def request(method: str, path: str, body: dict | None = None, retries: int = 5) -> dict:
    url = f"{OS_URL}{path}"
    data = json.dumps(body).encode() if body is not None else None
    last_err: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                url, data=data, method=method,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = resp.read().decode()
                return json.loads(payload) if payload.strip() else {}
        except urllib.error.HTTPError as e:  # 4xx are terminal
            detail = e.read().decode()[:400]
            raise RuntimeError(f"{method} {path} -> HTTP {e.code}: {detail}") from e
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last_err = e
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"{method} {path} failed after {retries} tries: {last_err}")


# ---------------------------------------------------------------- mappings
COMMON_EVENT_FIELDS = {
    "@timestamp": {"type": "date"},
    "ingest_time": {"type": "date"},
    "event_id": {"type": "keyword"},
    "sensor_id": {"type": "keyword"},
    "source_engine": {"type": "keyword"},
    "event_type": {"type": "keyword"},
    "event_subtype": {"type": "keyword"},
    "network_zone": {"type": "keyword"},
    "source": {
        "properties": {
            "ip": {"type": "ip"},
            "port": {"type": "integer"},
            "bytes": {"type": "long"},
            "packets": {"type": "long"},
            "geo": {"properties": {
                "country": {"type": "keyword"},
                "asn_org": {"type": "keyword"},
                "location": {"properties": {
                    "lat": {"type": "double"},
                    "lon": {"type": "double"},
                }},
            }},
        }
    },
    "destination": {
        "properties": {
            "ip": {"type": "ip"},
            "port": {"type": "integer"},
            "bytes": {"type": "long"},
            "packets": {"type": "long"},
            "geo": {"properties": {
                "country": {"type": "keyword"},
                "asn_org": {"type": "keyword"},
                "location": {"properties": {
                    "lat": {"type": "double"},
                    "lon": {"type": "double"},
                }},
            }},
        }
    },
    "network": {
        "properties": {
            "transport": {"type": "keyword"},
            "protocol": {"type": "keyword"},
            "bytes": {"type": "long"},
            "packets": {"type": "long"},
            "community_id": {"type": "keyword"},
        }
    },
    "severity": {"type": "keyword"},
    "severity_score": {"type": "short"},
    "signature_id": {"type": "keyword"},
    "rule_id": {"type": "keyword"},
    "category": {"type": "keyword"},
    "dedup_key": {"type": "keyword"},
    "session_id": {"type": "keyword"},
    "raw_event_ref": {"type": "keyword"},
    "parse_status": {"type": "keyword"},
    "parser_version": {"type": "keyword"},
    "dns": {
        "properties": {
            "query": {"type": "wildcard"},
            "type": {"type": "keyword"},
            "rcode": {"type": "keyword"},
            "answers": {
                "properties": {
                    "name": {"type": "keyword"},
                    "type": {"type": "keyword"},
                    "data": {"type": "keyword"},
                }
            },
        }
    },
    "http": {
        "properties": {
            "host": {"type": "keyword"},
            "url": {"type": "wildcard"},
            "method": {"type": "keyword"},
            "status_code": {"type": "integer"},
            "user_agent": {"type": "wildcard"},
            "referrer": {"type": "wildcard"},
        }
    },
    "tls": {
        "properties": {
            "sni": {"type": "keyword"},
            "version": {"type": "keyword"},
            "ja3": {"type": "keyword"},
            "subject": {"type": "keyword"},
            "issuer": {"type": "keyword"},
        }
    },
    "file": {
        "properties": {
            "name": {"type": "keyword"},
            "mime_type": {"type": "keyword"},
            "size": {"type": "long"},
            "hash": {"properties": {"md5": {"type": "keyword"},
                                     "sha1": {"type": "keyword"},
                                     "sha256": {"type": "keyword"}}},
        }
    },
    "alert": {
        "properties": {
            "signature": {"type": "keyword"},
            "category": {"type": "keyword"},
            "severity_id": {"type": "integer"},
            "gid": {"type": "integer"},
            "rev": {"type": "integer"},
        }
    },
    "matched_ioc": {
        "properties": {
            "ioc_type": {"type": "keyword"},
            "ioc_value": {"type": "wildcard"},
            "ioc_source": {"type": "keyword"},
            "confidence": {"type": "keyword"},
            "match_field": {"type": "keyword"},
        }
    },
}


def event_template(name: str, patterns: list[str], extra_aliases: dict) -> dict:
    # v0.12.5: `aliases` MUST live INSIDE `template` - at the top level of
    # a composable index template OpenSearch rejects the whole PUT with
    # "unknown field [aliases]" and bootstrap died on the FIRST template
    # -> zero templates/aliases/indices on the live VM.
    return {
        "index_patterns": patterns,
        "priority": 200,
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "refresh_interval": "10s",
                "index.plugins.index_state_management.policy_id": POLICY_ID,
            },
            "mappings": {
                "dynamic": False,
                "properties": COMMON_EVENT_FIELDS,
            },
            "aliases": {"ndr-events-read": {}, **extra_aliases},
        },
        "composed_of": [],
        "_meta": {"managed_by": "ndr-bootstrap", "retention_days": RETENTION_DAYS},
    }


ALERT_FIELDS = {
    # v0.12.5: the API time-filters and sorts every alert query on
    # @timestamp - without this mapping the shard order failed with
    # "No mapping found for [@timestamp] in order to sort on".
    "@timestamp": {"type": "date"},
    "alert_id": {"type": "keyword"},
    "alert_type": {"type": "keyword"},
    "title": {"type": "keyword"},
    "group_key": {"type": "keyword"},
    "severity": {"type": "keyword"},
    "severity_score": {"type": "short"},
    "status": {"type": "keyword"},
    "assignee": {"type": "keyword"},
    "confidence": {"type": "keyword"},
    "rationale": {"type": "text"},
    "reasons": {"type": "keyword"},
    "event_count": {"type": "long"},
    "source_count": {"type": "long"},
    "destination_count": {"type": "long"},
    "first_seen": {"type": "date"},
    "last_seen": {"type": "date"},
    "created_at": {"type": "date"},
    "updated_at": {"type": "date"},
    "updated_by": {"type": "keyword"},
    "notes": {"type": "text"},
    "sensor_id": {"type": "keyword"},
    "source": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}}},
    "destination": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}}},
    "network": {"properties": {"transport": {"type": "keyword"},
                                "protocol": {"type": "keyword"}}},
    "top_sources": {"properties": {"ip": {"type": "ip"}, "count": {"type": "long"}}},
    "top_destinations": {"properties": {"ip": {"type": "ip"}, "count": {"type": "long"}}},
    "top_rules": {"properties": {"signature": {"type": "keyword"},
                                  "signature_id": {"type": "keyword"},
                                  "count": {"type": "long"}}},
    "evidence": {
        "properties": {
            "event_id": {"type": "keyword"},
            "index": {"type": "keyword"},
            "@timestamp": {"type": "date"},
        }
    },
    "related_entities": {"type": "keyword"},
    # v0.14.0 alert whitelist: L1-tagged alerts carry these; the default
    # triage queue (UI) filters must_not suppressed unless explicitly shown.
    "suppressed": {"type": "boolean"},
    "suppressed_by": {"type": "integer"},
    # v0.14.0: structured sampled domains (DGA/NXDOMAIN/tunneling alerts)
    # so domain-entity whitelist entries can match retroactively.
    "dns_domains": {"type": "keyword"},
    "matched_iocs": {
        "properties": {
            "ioc_type": {"type": "keyword"},
            "ioc_value": {"type": "wildcard"},
            "ioc_source": {"type": "keyword"},
            "confidence": {"type": "keyword"},
            "match_field": {"type": "keyword"},
        }
    },
}


# v0.13.0: alias BACKFILL - attach read aliases onto EXISTING family
# indices from a previous deployment. Without this, aliases only covered
# the freshly bootstrapped indices and OLD data silently vanished from
# every view after an upgrade.
def backfill_aliases(es_client) -> int:
    touched = 0
    families = {
        "ndr-events-": "ndr-events-read",
        "ndr-alerts-": "ndr-alerts-read",
        "ndr-health-": "ndr-health-read",
        "ndr-ioc-matches-": "ndr-ioc-matches-read",
    }
    try:
        existing = set(es_client.indices.get_alias(index="*").keys())
    except Exception:
        return 0
    for prefix, alias in families.items():
        for index_name in sorted(existing):
            if not index_name.startswith(prefix) or index_name.endswith("-bootstrap"):
                continue
            try:
                info = es_client.indices.get_alias(index=index_name)
                if alias not in info[index_name].get("aliases", {}):
                    es_client.indices.put_alias(index=index_name, name=alias)
                    touched += 1
            except Exception:
                continue
    if touched:
        print(f"[bootstrap] alias backfill touched {touched} index(es)")
    return touched


def alert_template() -> dict:
    return {
        "index_patterns": ["ndr-alerts-*"],
        "priority": 200,
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "refresh_interval": "5s",
                "index.plugins.index_state_management.policy_id": POLICY_ID,
            },
            "mappings": {"dynamic": False, "properties": ALERT_FIELDS},
            "aliases": {"ndr-alerts-read": {}},
        },
        "_meta": {"managed_by": "ndr-bootstrap"},
    }


IOC_MATCH_FIELDS = {
    "@timestamp": {"type": "date"},
    "event_id": {"type": "keyword"},
    "event_index": {"type": "keyword"},
    "sensor_id": {"type": "keyword"},
    "ioc_type": {"type": "keyword"},
    "ioc_value": {"type": "wildcard"},
    "ioc_source": {"type": "keyword"},
    "ioc_confidence": {"type": "keyword"},
    "match_field": {"type": "keyword"},
    "first_seen": {"type": "date"},
    "last_seen": {"type": "date"},
    "expires_at": {"type": "date"},
    "source_ip": {"type": "ip"},
    "destination_ip": {"type": "ip"},
    "zone": {"type": "keyword"},
}


def ioc_matches_template() -> dict:
    return {
        "index_patterns": ["ndr-ioc-matches-*"],
        "priority": 200,
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "refresh_interval": "5s",
                "index.plugins.index_state_management.policy_id":
                    "ndr-ioc-retention",
            },
            "mappings": {"dynamic": False, "properties": IOC_MATCH_FIELDS},
            "aliases": {"ndr-ioc-matches-read": {}},
        },
        "_meta": {"managed_by": "ndr-bootstrap"},
    }


HEALTH_FIELDS = {
    "@timestamp": {"type": "date"},
    "sensor_id": {"type": "keyword"},
    "source_engine": {"type": "keyword"},
    "eps": {"type": "double"},
    "events_total": {"type": "long"},
    "events_indexed": {"type": "long"},
    "parse_errors": {"type": "long"},
    "duplicates": {"type": "long"},
    "dropped": {"type": "long"},
    "queue_depth": {"type": "long"},
    "queue_capacity": {"type": "long"},
    "backlog_seconds": {"type": "double"},
    "last_event_time": {"type": "date"},
    "tailer_state": {"type": "keyword"},
}


def health_template() -> dict:
    return {
        "index_patterns": ["ndr-health-*"],
        "priority": 200,
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "refresh_interval": "5s",
                "index.plugins.index_state_management.policy_id": POLICY_ID,
            },
            "mappings": {"dynamic": False, "properties": HEALTH_FIELDS},
            "aliases": {"ndr-health-read": {}},
        },
        "_meta": {"managed_by": "ndr-bootstrap"},
    }


def main() -> int:
    print(f"[bootstrap] target {OS_URL}, retention {RETENTION_DAYS}d")

    # 1. wait for cluster
    for attempt in range(20):
        try:
            health = request("GET", "/_cluster/health")
            print(f"[bootstrap] cluster status: {health.get('status')}")
            break
        except Exception as e:
            print(f"[bootstrap] waiting for cluster ({e})")
            time.sleep(5)
    else:
        print("[bootstrap] cluster never became available", file=sys.stderr)
        return 1

    # 2. ISM retention policy
    policy = {
        "policy": {
            "description": f"NDR retention: delete indices after {RETENTION_DAYS} days",
            "default_state": "hot",
            "states": [
                {
                    "name": "hot",
                    "actions": [],
                    "transitions": [
                        {"state_name": "delete", "conditions": {"min_index_age": f"{RETENTION_DAYS}d"}}
                    ],
                },
                {
                    "name": "delete",
                    "actions": [{"delete": {}}],
                    "transitions": [],
                },
            ],
            "ism_template": [],
        }
    }
    try:
        request("PUT", f"/_plugins/_ism/policies/{POLICY_ID}", policy)
        print(f"[bootstrap] ISM policy '{POLICY_ID}' created ({RETENTION_DAYS}d delete)")
    except RuntimeError as e:
        if "already exists" in str(e) or "version_conflict" in str(e):
            print(f"[bootstrap] ISM policy '{POLICY_ID}' already present")
        else:
            raise

    # ioc match indices use a 90d retention (doc 4: ndr-ioc-matches-*);
    # separate policy so metadata retention stays independent
    ioc_policy = json.loads(json.dumps(policy))
    ioc_policy["policy"]["description"] = (
        f"NDR IOC match retention: {IOC_RETENTION_DAYS} days")
    ioc_policy["policy"]["states"][0]["transitions"][0]["conditions"] = {
        "min_index_age": f"{IOC_RETENTION_DAYS}d"
    }
    try:
        request("PUT", "/_plugins/_ism/policies/ndr-ioc-retention", ioc_policy)
    except RuntimeError as e:
        if "already exists" not in str(e) and "version_conflict" not in str(e):
            raise

    # health indices use a shorter retention (separate policy)
    health_policy = json.loads(json.dumps(policy))
    health_policy["policy"]["description"] = (
        f"NDR pipeline health retention: {HEALTH_RETENTION_DAYS} days"
    )
    health_policy["policy"]["states"][0]["transitions"][0]["conditions"] = {
        "min_index_age": f"{HEALTH_RETENTION_DAYS}d"
    }
    try:
        request("PUT", "/_plugins/_ism/policies/ndr-health-retention", health_policy)
    except RuntimeError as e:
        if "already exists" not in str(e) and "version_conflict" not in str(e):
            raise

    # 3. templates
    templates = {
        "ndr-zeek-conn": event_template("ndr-zeek-conn", ["ndr-zeek-conn-*"],
                                        {"ndr-zeek-conn-read": {}}),
        "ndr-zeek-dns": event_template("ndr-zeek-dns", ["ndr-zeek-dns-*"],
                                       {"ndr-zeek-dns-read": {}}),
        "ndr-zeek-http": event_template("ndr-zeek-http", ["ndr-zeek-http-*"],
                                        {"ndr-zeek-http-read": {}}),
        "ndr-zeek-tls": event_template("ndr-zeek-tls", ["ndr-zeek-tls-*"],
                                       {"ndr-zeek-tls-read": {}}),
        "ndr-suricata": event_template("ndr-suricata", ["ndr-suricata-*"],
                                       {"ndr-suricata-read": {}}),
        "ndr-alerts": alert_template(),
        "ndr-ioc-matches": ioc_matches_template(),
        "ndr-health": {
            **health_template(),
            "template": {
                **health_template()["template"],
                "settings": {
                    **health_template()["template"]["settings"],
                    "index.plugins.index_state_management.policy_id": "ndr-health-retention",
                },
            },
        },
    }
    for name, body in templates.items():
        request("PUT", f"/_index_template/{name}", body)
        print(f"[bootstrap] template '{name}' installed")

    # 4. bootstrap indices so aliases resolve before the first ingest
    bootstrap_indices = {
        "ndr-zeek-conn": ["ndr-zeek-conn-read"],
        "ndr-zeek-dns": ["ndr-zeek-dns-read"],
        "ndr-zeek-http": ["ndr-zeek-http-read"],
        "ndr-zeek-tls": ["ndr-zeek-tls-read"],
        "ndr-suricata": ["ndr-suricata-read"],
        "ndr-alerts": ["ndr-alerts-read"],
        "ndr-ioc-matches": ["ndr-ioc-matches-read"],
        "ndr-health": ["ndr-health-read"],
    }
    for family, aliases in bootstrap_indices.items():
        idx = f"{family}-000000-bootstrap"
        exists = True
        try:
            request("GET", f"/{idx}")
        except RuntimeError:
            exists = False
        if not exists:
            try:
                request("PUT", f"/{idx}", {"aliases": {a: {} for a in aliases}})
                print(f"[bootstrap] bootstrap index '{idx}' created")
            except RuntimeError as e:
                if "resource_already_exists" not in str(e):
                    raise

    # 5. verify aliases
    aliases = request("GET", "/_cat/aliases?format=json")
    names = sorted({a["alias"] for a in aliases})
    print(f"[bootstrap] aliases present: {', '.join(names)}")
    try:
        backfill_aliases(es)
    except Exception as _e:
        print(f"[bootstrap] alias backfill skipped: {_e}")


    print("[bootstrap] done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
