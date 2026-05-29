"""
run.py - Layer 2 end-to-end CLI.

Read all ThreatArticle from src/collectors/threat_intel.db,
run pipeline: clean -> langdetect -> severity-infer -> dedup -> build STIX,
write to stix_objects + stix_relationships in the SAME DB.

Usage (from project root):
    python src/processing/run.py
    python src/processing/run.py --threshold 0.8
    python src/processing/run.py --limit 20
    python src/processing/run.py --reset
    python src/processing/run.py --allowed-langs en,vi,zh
"""
from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

# ──────────────────────────────────────────────
# PATH SETUP - must run BEFORE local imports
# ──────────────────────────────────────────────
_THIS_FILE   = Path(__file__).resolve()
_SRC_DIR     = _THIS_FILE.parents[1]
_PROJECT     = _THIS_FILE.parents[2]
_COLLECTORS  = _SRC_DIR / "collectors"
_DB_PATH     = _COLLECTORS / "threat_intel.db"

sys.path.insert(0, str(_SRC_DIR))
sys.path.insert(0, str(_COLLECTORS))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import ThreatArticle                                # Layer 1 model
from processing.schema import Base as ProcBase, StixObject
from processing.clean import (
    clean_text, normalize_severity, infer_severity_from_content,
    detect_language, to_utc,
)
from processing.dedup import find_clusters
from processing.report_builder import (
    build_report, build_grouping, source_identity, reset_identity_cache,
    tlp_clear_marking,
)

# ──────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────
logging.basicConfig(
    format="[L2 %(levelname).1s] %(message)s",
    level=logging.INFO,
)
log = logging.getLogger("processing.run")


def make_session():
    if not _DB_PATH.exists():
        sys.exit(f"[L2] ERROR: khong tim thay {_DB_PATH}. Layer 1 da chay chua?")
    engine = create_engine(
        f"sqlite:///{_DB_PATH}",
        connect_args={"check_same_thread": False},
    )
    ProcBase.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return engine, Session()


def run(threshold: float, limit: int | None, reset: bool,
        allowed_langs: set[str]) -> dict:
    """Run the L2 pipeline. Returns summary stats dict (for tests)."""
    engine, session = make_session()
    reset_identity_cache()

    if reset:
        n = session.query(StixObject).delete()
        session.commit()
        log.info("Reset: xoa %d stix_objects cu.", n)

    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)

    # ── 0. Persist TLP:WHITE marking definition once ─────────
    tlp = tlp_clear_marking()
    session.merge(StixObject(
        id=tlp.id, type=tlp.type, name="TLP:WHITE",
        created=now_utc, modified=now_utc,
        doc=tlp.serialize(),
    ))

    # ── 1. Load articles ─────────────────────────────────────
    q = session.query(ThreatArticle).order_by(ThreatArticle.id)
    if limit:
        q = q.limit(limit)
    articles = q.all()
    log.info("Loaded %d articles tu threat_articles.", len(articles))

    # ── 2. Clean + langdetect + severity normalize + infer ──
    cleaned: list[dict] = []
    n_inferred = 0
    n_lang_excluded = 0
    for a in articles:
        text = clean_text(a.raw_content)
        lang = detect_language(text)
        sev = normalize_severity(a.severity)
        if sev is None:
            inferred = infer_severity_from_content(a.source, a.raw_content)
            if inferred is not None:
                sev = inferred
                n_inferred += 1
        lang_excluded = lang not in allowed_langs
        if lang_excluded:
            n_lang_excluded += 1
        cleaned.append({
            "id":            a.id,
            "article":       a,
            "text":          text,
            "lang":          lang,
            "severity":      sev,
            "lang_excluded": lang_excluded,
            "content_hash":  a.content_hash,
        })
    log.info("Cleaned + langtagged %d articles. Severity inferred for %d row(s). "
             "Lang-excluded: %d.", len(cleaned), n_inferred, n_lang_excluded)

    # ── 3. Near-duplicate clustering ─────────────────────────
    clusters = find_clusters(
        [(c["id"], c["text"]) for c in cleaned],
        threshold=threshold,
    )
    canonical_ids = {cl[0] for cl in clusters}
    n_dupes = len(cleaned) - len(canonical_ids)
    log.info("Dedup (threshold=%s): %d clusters, %d canonical, "
             "%d near-duplicates collapsed.",
             threshold, len(clusters), len(canonical_ids), n_dupes)
    if n_dupes:
        multi = [cl for cl in clusters if len(cl) > 1][:5]
        for cl in multi:
            log.info("      cluster (canonical=%s): %s", cl[0], cl)

    by_id = {c["id"]: c for c in cleaned}

    # ── 4. Build STIX Report + Identity + Grouping, persist ─
    sev_counts: dict[str | None, int] = {}
    lang_counts: dict[str, int] = {}
    persisted_identities: set[str] = set()
    persisted_reports = 0
    persisted_groupings = 0

    for cluster in clusters:
        cluster_report_ids: list[str] = []

        for member_id in cluster:
            c = by_id[member_id]
            article = c["article"]

            # Identity
            identity = source_identity(article.source)
            if identity.id not in persisted_identities:
                session.merge(StixObject(
                    id=identity.id, type=identity.type, name=identity.name,
                    source=article.source,
                    created=now_utc, modified=now_utc,
                    doc=identity.serialize(),
                ))
                persisted_identities.add(identity.id)

            # Report - build cho TAT CA cluster member
            report = build_report(
                article=article,
                clean_content=c["text"],
                lang=c["lang"],
                severity=c["severity"],
                content_hash=c["content_hash"],
                lang_excluded=c["lang_excluded"],
            )
            session.merge(StixObject(
                id=report.id, type=report.type, name=report.name,
                source=article.source,
                severity=c["severity"], lang=c["lang"],
                published=to_utc(article.published_at).replace(tzinfo=None),
                created=now_utc, modified=now_utc,
                raw_article_id=str(article.id),
                doc=report.serialize(),
            ))
            cluster_report_ids.append(report.id)
            persisted_reports += 1
            sev_counts[c["severity"]] = sev_counts.get(c["severity"], 0) + 1
            lang_counts[c["lang"]]    = lang_counts.get(c["lang"], 0) + 1

        # Grouping for multi-member clusters
        if len(cluster_report_ids) > 1:
            grouping = build_grouping(
                canonical_report_id=cluster_report_ids[0],
                member_report_ids=cluster_report_ids,
                context="same-incident",
            )
            session.merge(StixObject(
                id=grouping.id, type=grouping.type, name=grouping.name,
                source=None,
                created=now_utc, modified=now_utc,
                doc=grouping.serialize(),
            ))
            persisted_groupings += 1

    session.commit()

    # ── 5. Summary ───────────────────────────────────────────
    summary = {
        "identities":   len(persisted_identities),
        "reports":      persisted_reports,
        "groupings":    persisted_groupings,
        "severity_inferred": n_inferred,
        "lang_excluded":     n_lang_excluded,
        "severity_counts":   sev_counts,
        "lang_counts":       lang_counts,
    }
    log.info("DONE. %d identities + %d reports + %d groupings + 1 TLP marking -> %s",
             summary["identities"], summary["reports"], summary["groupings"],
             _DB_PATH.name)
    log.info("Severity distribution: %s", sev_counts)
    log.info("Language distribution: %s", lang_counts)

    session.close()
    engine.dispose()
    return summary


def main() -> None:
    ap = argparse.ArgumentParser(description="Layer 2 - Normalization & Cleaning")
    ap.add_argument("--threshold", type=float, default=0.85,
                    help="Jaccard threshold cho near-duplicate (default 0.85)")
    ap.add_argument("--limit", type=int, default=None,
                    help="Chi xu ly N articles dau (debug)")
    ap.add_argument("--reset", action="store_true",
                    help="Xoa stix_objects cu truoc khi chay")
    ap.add_argument("--allowed-langs", type=str, default="en,vi",
                    help="Comma-separated ISO 639-1 lang codes giu lai cho RAG "
                         "(default en,vi). Bai lang khac van persist nhung "
                         "danh dau x_lang_excluded=True.")
    args = ap.parse_args()
    allowed = {x.strip().lower() for x in args.allowed_langs.split(",") if x.strip()}
    run(threshold=args.threshold, limit=args.limit, reset=args.reset,
        allowed_langs=allowed)


if __name__ == "__main__":
    main()
