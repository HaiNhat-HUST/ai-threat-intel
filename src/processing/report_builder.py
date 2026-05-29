"""
report_builder.py - Build STIX 2.1 Identity, Report, and Grouping SDOs.

Layer 2 emits four object types now:
    identity            - one per source (CISA KEV, NVD, ...). Cached.
    report              - one per article (all cluster members, not just canonical).
    grouping            - one per multi-member dedup cluster (same-incident).
    marking-definition  - TLP:WHITE, persisted once, referenced by every Report.

DETERMINISTIC IDs:
    UUIDv5 with a fixed namespace so re-running the pipeline produces
    the same id for the same input - making SQLAlchemy session.merge()
    idempotent (UPSERT on PK).

Public API:
    source_identity(source: str) -> Identity
    tlp_clear_marking() -> MarkingDefinition
    build_report(article, clean_text, lang, severity, lang_excluded=False) -> Report
    build_grouping(canonical_report_id, member_report_ids, context) -> Grouping
"""
from __future__ import annotations

import uuid
from stix2 import (
    Identity, Report, ExternalReference, Grouping, TLP_WHITE,
)

from .clean import to_stix_timestamp


# Project namespace UUID. Hardcoded value of:
#   uuid.uuid5(uuid.NAMESPACE_DNS, "ai-threat-intel.hust.edu.vn")
_PROJECT_NS = uuid.UUID("016ec563-fd65-5ca2-bfd7-4c12b31261b2")


def _det_uuid(*parts: str) -> uuid.UUID:
    key = "|".join(str(p) for p in parts)
    return uuid.uuid5(_PROJECT_NS, key)


def _det_id(stix_type: str, *parts: str) -> str:
    return f"{stix_type}--{_det_uuid(stix_type, *parts)}"


# Identity cache (one per source)
_identity_cache: dict[str, Identity] = {}


def source_identity(source: str) -> Identity:
    """Idempotent identity per source name."""
    if source in _identity_cache:
        return _identity_cache[source]
    ident = Identity(
        id=_det_id("identity", "source", source),
        name=source,
        identity_class="organization",
        allow_custom=True,
    )
    _identity_cache[source] = ident
    return ident


def reset_identity_cache() -> None:
    """Allow tests to reset the cache."""
    _identity_cache.clear()


def tlp_clear_marking():
    """
    TLP:WHITE marking-definition (well-known STIX object).
    All Reports from public feeds get object_marking_refs=[tlp.id]
    so downstream consumers know the sharing level.
    """
    return TLP_WHITE


def build_grouping(canonical_report_id: str, member_report_ids: list,
                   context: str = "same-incident") -> Grouping:
    """
    Emit a STIX Grouping SDO that bundles multiple Reports about the same incident.

    Khi dedup phat hien nhieu nguon cung dua tin ve 1 su kien, ta giu lai
    tat ca Report va them mot Grouping object_refs tro toi tat ca, de
    Layer 5 RAG co du bang chung va dashboard hien duoc "vu nay co N nguon".

    Deterministic id: cluster co cung canonical -> cung Grouping id.
    """
    return Grouping(
        id=_det_id("grouping", canonical_report_id),
        name=f"Same-incident cluster ({len(member_report_ids)} sources)",
        context=context,
        object_refs=member_report_ids,
        allow_custom=True,
    )


def build_report(article, clean_content: str, lang: str, severity,
                 content_hash: str | None = None,
                 lang_excluded: bool = False):
    """
    Build a STIX 2.1 Report SDO from one ThreatArticle.

    object_refs starts with just the source identity - Layer 3 appends
    indicator/malware/vulnerability/attack-pattern objects later.

    Custom properties (x_ prefix):
        x_severity       - normalized severity (critical/high/medium/low/info/None)
        x_raw_article_id - id from threat_articles table for back-reference
        x_content_hash   - Hung's SHA-256 hash (exact-match dedup for Layer 3)
        x_lang_excluded  - True if lang not in allowed list (Layer 6 may skip embedding)
    """
    identity = source_identity(article.source)

    extras = {}
    if content_hash:
        extras["x_content_hash"] = content_hash
    if lang_excluded:
        extras["x_lang_excluded"] = True

    return Report(
        id=_det_id("report", article.source, article.url),
        created_by_ref=identity.id,
        name=article.title,
        description=clean_content,
        published=to_stix_timestamp(article.published_at),
        report_types=["threat-report"],
        object_refs=[identity.id],
        external_references=[
            ExternalReference(source_name=article.source, url=article.url),
        ],
        object_marking_refs=[TLP_WHITE.id],
        lang=lang or "en",
        x_severity=severity,
        x_raw_article_id=str(article.id),
        allow_custom=True,
        **extras,
    )
