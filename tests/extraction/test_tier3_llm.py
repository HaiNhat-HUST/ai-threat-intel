"""Unit tests cho Tier 3 — MockProvider + enrich_report pipeline."""
from extraction.llm.factory import get_provider
from extraction.llm.mock import MockProvider
from extraction.tier3_llm import enrich_report
from extraction.attack_kb import TECHNIQUE_BY_ID, attack_url


# ─── MockProvider.classify_attack_pattern ───────

def test_classify_supply_chain():
    p = MockProvider()
    out = p.classify_attack_pattern(
        "Grafana breach via TanStack npm supply chain attack"
    )
    ids = {t["id"] for t in out}
    assert "T1195.002" in ids
    # Cấp parent T1195 cũng nên match
    assert "T1195" in ids


def test_classify_ransomware():
    p = MockProvider()
    out = p.classify_attack_pattern(
        "LockBit ransomware encrypts files and demands ransom"
    )
    assert any(t["id"] == "T1486" for t in out)


def test_classify_phishing():
    p = MockProvider()
    out = p.classify_attack_pattern(
        "Spearphishing attachment delivered via macro-enabled document"
    )
    assert any(t["id"] == "T1566.001" for t in out)


def test_classify_no_match():
    p = MockProvider()
    out = p.classify_attack_pattern("Discussion about cryptocurrency markets.")
    assert out == []


def test_classify_empty():
    p = MockProvider()
    assert p.classify_attack_pattern("") == []


# ─── MockProvider.infer_relationships ───────────

def test_infer_actor_uses_malware():
    p = MockProvider()
    entities = {
        "threat_actor_ids": ["threat-actor--11111111-1111-4111-8111-111111111111"],
        "malware_ids":      ["malware--22222222-2222-4222-8222-222222222222"],
    }
    rels = p.infer_relationships(entities)
    assert any(r["relationship_type"] == "uses"
               and r["source_ref"].startswith("threat-actor")
               and r["target_ref"].startswith("malware")
               for r in rels)


def test_infer_attack_pattern_targets_vuln():
    p = MockProvider()
    entities = {
        "attack_pattern_ids": ["attack-pattern--11111111-1111-4111-8111-111111111111"],
        "vulnerability_ids":  ["vulnerability--22222222-2222-4222-8222-222222222222"],
    }
    rels = p.infer_relationships(entities)
    assert any(r["relationship_type"] == "targets" for r in rels)


def test_infer_no_entities_no_rels():
    p = MockProvider()
    assert p.infer_relationships({}) == []


# ─── MockProvider.infer_severity ────────────────

def test_severity_critical_keywords():
    p = MockProvider()
    assert p.infer_severity("pre-auth RCE allowing remote takeover") == "critical"
    assert p.infer_severity("actively exploited zero-day") == "critical"


def test_severity_high():
    p = MockProvider()
    assert p.infer_severity("High severity vulnerability") == "high"
    assert p.infer_severity("Privilege escalation issue") == "high"


def test_severity_low():
    p = MockProvider()
    assert p.infer_severity("Low severity informational finding") == "low"


def test_severity_none_on_neutral_text():
    p = MockProvider()
    assert p.infer_severity("Software update released today.") is None


# ─── attack_kb.py sanity ────────────────────────

def test_attack_kb_has_supply_chain():
    assert "T1195.002" in TECHNIQUE_BY_ID


def test_attack_kb_url_builder():
    assert attack_url("T1190") == "https://attack.mitre.org/techniques/T1190/"
    assert attack_url("T1566.001") == "https://attack.mitre.org/techniques/T1566/001/"


# ─── factory.py ────────────────────────────────

def test_factory_default_is_mock():
    p = get_provider()
    assert p.name == "mock"


def test_factory_explicit_mock():
    p = get_provider("mock")
    assert p.name == "mock"


def test_factory_unknown_raises():
    import pytest
    with pytest.raises(ValueError):
        get_provider("nonexistent-provider")


# ─── enrich_report full pipeline ────────────────

_FAKE = "11111111-1111-4111-8111-111111111111"
_FAKE2 = "22222222-2222-4222-8222-222222222222"


def test_enrich_pipeline_end_to_end():
    p = MockProvider()
    tier1 = {
        "vulnerability_ids": [f"vulnerability--{_FAKE}"],
        "indicator_ids":     [f"indicator--{_FAKE}"],
    }
    tier2 = {
        "threat_actor_ids":  [f"threat-actor--{_FAKE2}"],
        "malware_ids":       [f"malware--{_FAKE2}"],
        "tool_ids":          [],
    }
    out = enrich_report(
        "Supply chain attack with pre-auth RCE in build pipeline",
        tier1, tier2, p,
    )
    # Attack-pattern SDOs emitted
    assert len(out["attack_patterns"]) > 0
    assert any("supply" in ap.name.lower() for ap in out["attack_patterns"])
    # Relationships emitted
    assert len(out["relationships"]) > 0
    # Severity inferred as critical
    assert out["severity"] == "critical"


def test_enrich_idempotent_attack_pattern_ids():
    """Cùng technique → cùng Attack-Pattern id qua các call."""
    p = MockProvider()
    out1 = enrich_report("ransomware encrypts files", {}, {}, p)
    out2 = enrich_report("ransomware encrypts files", {}, {}, p)
    ids1 = {ap.id for ap in out1["attack_patterns"]}
    ids2 = {ap.id for ap in out2["attack_patterns"]}
    assert ids1 == ids2
