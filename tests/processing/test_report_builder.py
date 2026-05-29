"""Unit tests cho report_builder.py - deterministic ids + STIX validation."""
import json
from datetime import datetime
from types import SimpleNamespace

import pytest
from stix2 import parse as stix_parse

from processing.report_builder import (
    source_identity, reset_identity_cache,
    build_report, build_grouping, tlp_clear_marking,
    _det_id,
)

# Use valid UUID-format STIX ids for test fixtures
_FAKE_RID_1 = "report--11111111-1111-4111-8111-111111111111"
_FAKE_RID_2 = "report--22222222-2222-4222-8222-222222222222"
_FAKE_RID_3 = "report--33333333-3333-4333-8333-333333333333"


@pytest.fixture(autouse=True)
def _clear_cache():
    reset_identity_cache()
    yield
    reset_identity_cache()


@pytest.fixture
def sample_article():
    return SimpleNamespace(
        id=1,
        title="Test CVE-2026-12345",
        source="CISA KEV",
        url="https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
        raw_content="Critical RCE vulnerability in Exchange",
        content_hash="a5e67b02b0d931c9c229c4a71289810f6a33d6e4ab5408a2f077f3fbd10a3610",
        severity="CRITICAL",
        published_at=datetime(2026, 5, 15, 0, 0, 0),
    )


# ─── Deterministic IDs ──────────────────────────

def test_det_id_format():
    rid = _det_id("report", "CISA KEV", "https://example.com")
    assert rid.startswith("report--")
    assert len(rid.split("--")[1]) == 36


def test_det_id_idempotent():
    a = _det_id("report", "CISA KEV", "https://example.com")
    b = _det_id("report", "CISA KEV", "https://example.com")
    assert a == b


def test_det_id_changes_with_input():
    a = _det_id("report", "CISA KEV", "https://example.com/a")
    b = _det_id("report", "CISA KEV", "https://example.com/b")
    assert a != b


# ─── Identity ───────────────────────────────────

def test_source_identity_cached():
    a = source_identity("CISA KEV")
    b = source_identity("CISA KEV")
    assert a is b


def test_source_identity_id_deterministic():
    a = source_identity("CISA KEV")
    reset_identity_cache()
    b = source_identity("CISA KEV")
    assert a.id == b.id


# ─── Report ─────────────────────────────────────

def test_build_report_validates_via_stix2(sample_article):
    r = build_report(sample_article, "clean text", "en", "critical",
                     content_hash=sample_article.content_hash)
    parsed = stix_parse(r.serialize(), allow_custom=True)
    assert parsed.type == "report"
    assert parsed.lang == "en"


def test_build_report_has_tlp_marking(sample_article):
    r = build_report(sample_article, "clean text", "en", "critical")
    doc = json.loads(r.serialize())
    assert "object_marking_refs" in doc
    assert tlp_clear_marking().id in doc["object_marking_refs"]


def test_build_report_carries_content_hash(sample_article):
    r = build_report(sample_article, "clean text", "en", "critical",
                     content_hash=sample_article.content_hash)
    doc = json.loads(r.serialize())
    assert doc["x_content_hash"] == sample_article.content_hash


def test_build_report_lang_excluded_flag(sample_article):
    r = build_report(sample_article, "clean text", "ja", None,
                     lang_excluded=True)
    doc = json.loads(r.serialize())
    assert doc.get("x_lang_excluded") is True


def test_build_report_no_lang_excluded_when_false(sample_article):
    r = build_report(sample_article, "clean text", "en", "critical",
                     lang_excluded=False)
    doc = json.loads(r.serialize())
    assert "x_lang_excluded" not in doc


# ─── Grouping ───────────────────────────────────

def test_grouping_object_refs():
    g = build_grouping(_FAKE_RID_1, [_FAKE_RID_1, _FAKE_RID_2, _FAKE_RID_3])
    doc = json.loads(g.serialize())
    assert doc["context"] == "same-incident"
    assert len(doc["object_refs"]) == 3
    assert _FAKE_RID_2 in doc["object_refs"]


def test_grouping_id_deterministic():
    a = build_grouping(_FAKE_RID_1, [_FAKE_RID_1, _FAKE_RID_2])
    b = build_grouping(_FAKE_RID_1, [_FAKE_RID_1, _FAKE_RID_2])
    assert a.id == b.id
