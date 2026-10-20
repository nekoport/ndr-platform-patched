"""Threat Intelligence subsystem (doc section 9 - Phase 3).

Components:
  * feeds.py     - feed adapters (fetch + normalize + validate IOCs)
  * store.py     - SQL-backed IOC store (provenance, dedup, expiry, jobs)
  * matcher.py   - in-memory IOC matcher with atomic snapshot reload
  * collector.py - IntelService thread: job queue consumer + scheduler

Design guardrails (doc 9.2 / 9.3):
  * IOC match is contextual evidence, never automatic proof of compromise.
  * A failed feed must never silently delete or expire valid IOCs.
  * Expired IOCs are marked, not removed; allowlist workflow is auditable.
"""
