"""
run.py - Layer 3 (Tier 1 + 2 + 3) end-to-end CLI.

For each Report SDO in stix_objects:
    Tier 1 - extract_iocs()    -> Indicator / Vulnerability
    Tier 2 - extract_entities()-> Malware / Threat-Actor / Tool
              + relationships  indicator -indicates-> malware
    Tier 3 - LLM provider      -> Attack-Pattern SDOs
              + relationships  actor uses malware,
                                malware uses attack-pattern,
                                attack-pattern targets vulnerability
              + severity        infer when None

LLM provider chọn qua env LLM_PROVIDER (default 'mock').

Usage:
    python src/extraction/run.py
    python src/extraction/run.py --tier 1
    python src/extraction/run.py --tier 1,2
    python src/extraction/run.py --tier 1,2,3
    python src/extraction/run.py --reset
    LLM_PROVIDER=claude python src/extraction/run.py    # khi co adapter
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

_THIS_FILE  = Path(__file__).resolve()
_SRC_DIR    = _THIS_FILE.parents[1]
_COLLECTORS = _SRC_DIR / "collectors"
_DB_PATH    = _COLLECTORS / "threat_intel.db"

sys.path.insert(0, str(_SRC_DIR))
sys.path.insert(0, str(_COLLECTORS))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from processing.schema import Base as ProcBase, StixObject, StixRelationship
from extraction.tier1_regex import extract_iocs
from extraction.tier2_ner import extract_entities
from extraction.tier3_llm import enrich_report
from extraction.llm.factory import get_provider
from extraction import builders

logging.basicConfig(format="[L3 %(levelname).1s] %(message)s", level=logging.INFO)
log = logging.getLogger("extraction.run")


# ──────────────────────────────────────────────
# SDO factory dispatch
# ──────────────────────────────────────────────

def _build_tier1_sdo(ioc: tuple):
    kind, *rest = ioc
    if kind == "cve":       return builders.build_vulnerability(rest[0])
    if kind == "ipv4":      return builders.build_indicator_ipv4(rest[0])
    if kind == "ipv6":      return builders.build_indicator_ipv6(rest[0])
    if kind == "domain":    return builders.build_indicator_domain(rest[0])
    if kind == "url":       return builders.build_indicator_url(rest[0])
    if kind == "file_hash": return builders.build_indicator_file_hash(rest[0], rest[1])
    if kind == "email":     return builders.build_indicator_email(rest[0])
    if kind == "btc":       return builders.build_indicator_btc(rest[0])
    return None


def _build_tier2_sdo(entity: tuple):
    kind, name, types = entity
    if kind == "malware":      return builders.build_malware(name, malware_types=types)
    if kind == "threat_actor": return builders.build_threat_actor(name, threat_actor_types=types)
    if kind == "tool":         return builders.build_tool(name, tool_types=types)
    return None


def make_session():
    if not _DB_PATH.exists():
        sys.exit(f"[L3] ERROR: not found {_DB_PATH}. Run Layer 2 first.")
    engine = create_engine(f"sqlite:///{_DB_PATH}",
                           connect_args={"check_same_thread": False})
    ProcBase.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return engine, Session()


def _persist_entity(session, sdo, seen_entities, now_utc, **extra):
    """Idempotent merge into stix_objects."""
    if sdo.id in seen_entities:
        return False
    session.merge(StixObject(
        id=sdo.id, type=sdo.type, name=getattr(sdo, "name", None),
        created=now_utc, modified=now_utc,
        doc=sdo.serialize(),
        **extra,
    ))
    seen_entities.add(sdo.id)
    return True


def _persist_relationship(session, rel, seen_relationships, now_utc):
    if rel.id in seen_relationships:
        return False
    session.merge(StixRelationship(
        id=rel.id,
        source_ref=rel.source_ref, target_ref=rel.target_ref,
        relationship_type=rel.relationship_type,
        created=now_utc, modified=now_utc,
        doc=rel.serialize(),
    ))
    seen_relationships.add(rel.id)
    return True


# ──────────────────────────────────────────────
# PIPELINE
# ──────────────────────────────────────────────

def run(limit: int | None, reset: bool, tiers: set[int],
        llm_provider_name: str | None = None) -> dict:
    engine, session = make_session()
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)

    if reset:
        n_obj = (session.query(StixObject)
                        .filter(StixObject.type.in_(
                            ["indicator", "vulnerability",
                             "malware", "threat-actor", "tool",
                             "attack-pattern"]))
                        .delete(synchronize_session=False))
        n_rel = session.query(StixRelationship).delete(synchronize_session=False)
        session.commit()
        log.info("Reset: xoa %d entity + %d relationship cu.", n_obj, n_rel)

    provider = get_provider(llm_provider_name) if 3 in tiers else None
    if provider:
        log.info("LLM provider: %s", provider.name)

    q = session.query(StixObject).filter_by(type="report")
    if limit:
        q = q.limit(limit)
    reports = q.all()
    log.info("Loaded %d reports. Tiers: %s", len(reports), sorted(tiers))

    seen_entities: set[str] = set()
    seen_relationships: set[str] = set()
    kind_counts: dict[str, int] = {}
    n_entities = 0
    n_relationships = 0
    n_severity_inferred = 0
    updated_reports = 0

    for r in reports:
        doc = json.loads(r.doc)
        description = doc.get("description", "")
        original_refs = list(doc.get("object_refs", []))
        new_refs: list[str] = list(original_refs)

        tier1_indicator_ids: list[str] = []
        tier1_vulnerability_ids: list[str] = []
        tier2_malware_ids: list[str] = []
        tier2_actor_ids: list[str] = []
        tier2_tool_ids: list[str] = []

        # ── TIER 1 ───────────────────────────────────
        if 1 in tiers:
            for ioc in extract_iocs(description, source=r.source):
                sdo = _build_tier1_sdo(ioc)
                if sdo is None:
                    continue
                kind = ioc[0]
                kind_counts[kind] = kind_counts.get(kind, 0) + 1
                if _persist_entity(session, sdo, seen_entities, now_utc):
                    n_entities += 1
                if sdo.id not in new_refs:
                    new_refs.append(sdo.id)
                if sdo.type == "indicator":     tier1_indicator_ids.append(sdo.id)
                if sdo.type == "vulnerability": tier1_vulnerability_ids.append(sdo.id)

        # ── TIER 2 ───────────────────────────────────
        if 2 in tiers:
            for entity in extract_entities(description, source=r.source):
                sdo = _build_tier2_sdo(entity)
                if sdo is None:
                    continue
                kind = entity[0]
                kind_counts[kind] = kind_counts.get(kind, 0) + 1
                if _persist_entity(session, sdo, seen_entities, now_utc):
                    n_entities += 1
                if sdo.id not in new_refs:
                    new_refs.append(sdo.id)
                if sdo.type == "malware":      tier2_malware_ids.append(sdo.id)
                if sdo.type == "threat-actor": tier2_actor_ids.append(sdo.id)
                if sdo.type == "tool":         tier2_tool_ids.append(sdo.id)

            # Indicator -indicates-> Malware (in same report)
            for ind_id in tier1_indicator_ids:
                for mal_id in tier2_malware_ids:
                    rel = builders.build_relationship(ind_id, mal_id, "indicates")
                    if _persist_relationship(session, rel, seen_relationships, now_utc):
                        n_relationships += 1

        # ── TIER 3 ───────────────────────────────────
        tier3_severity = None
        if 3 in tiers and provider:
            tier1_e = {
                "vulnerability_ids": tier1_vulnerability_ids,
                "indicator_ids":     tier1_indicator_ids,
            }
            tier2_e = {
                "threat_actor_ids":  tier2_actor_ids,
                "malware_ids":       tier2_malware_ids,
                "tool_ids":          tier2_tool_ids,
            }
            enriched = enrich_report(description, tier1_e, tier2_e, provider)

            # Persist Attack-Pattern SDOs
            for ap in enriched["attack_patterns"]:
                kind_counts["attack_pattern"] = kind_counts.get("attack_pattern", 0) + 1
                if _persist_entity(session, ap, seen_entities, now_utc):
                    n_entities += 1
                if ap.id not in new_refs:
                    new_refs.append(ap.id)

            # Persist Relationships
            for rel_info in enriched["relationships"]:
                rel = rel_info["sdo"]
                if _persist_relationship(session, rel, seen_relationships, now_utc):
                    n_relationships += 1

            # Severity (chỉ ghi đè khi Layer 2 để None)
            if enriched["severity"] and not r.severity:
                tier3_severity = enriched["severity"]
                r.severity = tier3_severity
                doc["x_severity"] = tier3_severity
                n_severity_inferred += 1

        # Update report's object_refs / doc
        doc_changed = False
        if new_refs != original_refs:
            doc["object_refs"] = new_refs
            doc_changed = True
        if tier3_severity:
            doc_changed = True
        if doc_changed:
            doc["modified"] = now_utc.isoformat() + "Z"
            r.doc = json.dumps(doc)
            r.modified = now_utc
            updated_reports += 1

    session.commit()
    log.info("DONE. %d entities, %d relationships persisted. "
             "Severity inferred (Tier 3): %d. Updated %d reports.",
             n_entities, n_relationships, n_severity_inferred, updated_reports)
    log.info("Kind breakdown: %s", kind_counts)
    session.close(); engine.dispose()
    return {
        "entities":           n_entities,
        "relationships":      n_relationships,
        "severity_inferred":  n_severity_inferred,
        "kinds":              kind_counts,
        "updated_reports":    updated_reports,
    }


def main():
    ap = argparse.ArgumentParser(description="Layer 3 - Entity Extraction (Tier 1/2/3)")
    ap.add_argument("--limit", type=int, default=None, help="N reports dau (debug)")
    ap.add_argument("--reset", action="store_true",
                    help="Xoa L3 entity + relationship cu truoc khi chay")
    ap.add_argument("--tier", type=str, default="1,2,3",
                    help="Comma-separated tiers to run (default '1,2,3')")
    ap.add_argument("--llm-provider", type=str, default=None,
                    help="Override env LLM_PROVIDER (mock/claude/openai/ollama)")
    args = ap.parse_args()
    tiers = {int(x) for x in args.tier.split(",") if x.strip()}
    run(limit=args.limit, reset=args.reset, tiers=tiers,
        llm_provider_name=args.llm_provider)


if __name__ == "__main__":
    main()
