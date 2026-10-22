"""NDR event pipeline - Phase 0-5 (attack reconstruction + threat map).

Ingests Suricata EVE JSON and Zeek JSON logs, normalizes them into a
common event schema, validates, deduplicates, enriches (zones, optional
GeoIP), applies baseline detection heuristics, reconstructs attack
stories, and bulk-indexes into OpenSearch.

Design refs: NDR System Design & Implementation Plan v1.0
  * section 7  (event pipeline stages)
  * section 6  (entity / event attributes)
  * section 8.1 (dedup vs aggregation)
  * section 8.7 (DGA heuristics - baseline NXDOMAIN burst rule)
"""

__version__ = "0.16.0"
# v0.14.0: selaras dgn models.py (single value; dulu 0.6.0 membuat log
# startup & health doc menampilkan parser version beda dari event docs)
PARSER_VERSION = "ndr-pipeline/0.7.0"
