"""Unit tests cho extraction/builders.py."""
import json

import pytest
from stix2 import parse as stix_parse

from extraction import builders


def test_ipv4_indicator_deterministic():
    a = builders.build_indicator_ipv4("1.2.3.4")
    b = builders.build_indicator_ipv4("1.2.3.4")
    assert a.id == b.id


def test_ipv4_indicator_validates():
    i = builders.build_indicator_ipv4("60.204.249.248")
    parsed = stix_parse(i.serialize(), allow_custom=True)
    assert parsed.type == "indicator"
    assert parsed.pattern == "[ipv4-addr:value = '60.204.249.248']"


def test_sha256_indicator():
    h = "a5e67b02b0d931c9c229c4a71289810f6a33d6e4ab5408a2f077f3fbd10a3610"
    i = builders.build_indicator_file_hash("sha256", h)
    doc = json.loads(i.serialize())
    assert "file:hashes.'SHA-256'" in doc["pattern"]
    assert h in doc["pattern"]


def test_md5_indicator():
    h = "b60dd51e91841ea346b7a66aa97e9265"
    i = builders.build_indicator_file_hash("md5", h)
    assert "file:hashes.MD5" in i.pattern


def test_url_indicator():
    i = builders.build_indicator_url("https://evil.com/c2")
    parsed = stix_parse(i.serialize(), allow_custom=True)
    assert parsed.type == "indicator"


def test_domain_lowercased():
    a = builders.build_indicator_domain("Evil.COM")
    b = builders.build_indicator_domain("evil.com")
    assert a.id == b.id      # case-insensitive id


def test_vulnerability_has_cve_ext_ref():
    v = builders.build_vulnerability("CVE-2026-42897")
    doc = json.loads(v.serialize())
    refs = doc["external_references"]
    assert any(r["source_name"] == "cve" and r["external_id"] == "CVE-2026-42897"
               for r in refs)


def test_vulnerability_id_deterministic():
    a = builders.build_vulnerability("CVE-2026-42897")
    b = builders.build_vulnerability("cve-2026-42897")  # case-insensitive
    assert a.id == b.id


def test_relationship_deterministic():
    a = builders.build_relationship(
        "indicator--11111111-1111-4111-8111-111111111111",
        "malware--22222222-2222-4222-8222-222222222222",
        "indicates",
    )
    b = builders.build_relationship(
        "indicator--11111111-1111-4111-8111-111111111111",
        "malware--22222222-2222-4222-8222-222222222222",
        "indicates",
    )
    assert a.id == b.id


def test_unknown_hash_type_raises():
    with pytest.raises(ValueError):
        builders.build_indicator_file_hash("blake2", "abc123")


# ─── Tier 2 builders ────────────────────────────

def test_build_malware_deterministic():
    a = builders.build_malware("LockBit")
    b = builders.build_malware("lockbit")
    assert a.id == b.id


def test_build_malware_validates():
    m = builders.build_malware("LockBit", malware_types=["ransomware"])
    parsed = stix_parse(m.serialize(), allow_custom=True)
    assert parsed.type == "malware"
    assert parsed.name == "LockBit"
    assert parsed.is_family is True


def test_build_threat_actor_deterministic():
    a = builders.build_threat_actor("APT29")
    b = builders.build_threat_actor("apt29")
    assert a.id == b.id


def test_build_tool_validates():
    t = builders.build_tool("Cobalt Strike", tool_types=["exploitation"])
    parsed = stix_parse(t.serialize(), allow_custom=True)
    assert parsed.type == "tool"
    assert parsed.name == "Cobalt Strike"
