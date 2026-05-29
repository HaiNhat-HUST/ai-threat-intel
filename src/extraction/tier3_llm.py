"""
tier3_llm.py - Layer 3 Tier 3 pipeline.

Sau khi Tier 1+2 đã rút entity và Relationship cơ bản (indicator-indicates-malware),
Tier 3 dùng LLM provider để:

    1. classify_attack_pattern(description) → Attack-Pattern SDOs (T1190, ...)
    2. infer_relationships(entities) → quan hệ giữa các entity type:
         threat-actor uses malware, malware uses attack-pattern,
         attack-pattern targets vulnerability, ...
    3. infer_severity(description) → suy severity cho Report None

Provider lấy từ env LLM_PROVIDER (default 'mock'). Pipeline KHÔNG biết
mock hay claude — nhờ Protocol.

Public API:
    enrich_report(description, tier1_entities, tier2_entities, provider)
        -> dict with attack_patterns, relationships, severity
"""
from __future__ import annotations

from extraction import builders


def enrich_report(
    description: str,
    tier1_entities: dict,         # {"vulnerability_ids": [...], "indicator_ids": [...]}
    tier2_entities: dict,         # {"malware_ids": [...], "threat_actor_ids": [...], "tool_ids": [...]}
    provider,                     # LLMProvider
) -> dict:
    """
    Return:
        {
          "attack_patterns": [AttackPattern SDO, ...],
          "relationships":   [{"source_ref": id, "target_ref": id,
                               "relationship_type": ..., "sdo": Relationship}, ...],
          "severity":        str | None,
        }
    """
    out_attacks: list = []
    out_rels: list[dict] = []

    # 1. Classify attack patterns
    attack_pattern_ids: list[str] = []
    for entry in provider.classify_attack_pattern(description):
        ap = builders.build_attack_pattern(
            technique_id=entry["id"],
            name=entry["name"],
            tactic=entry.get("tactic"),
        )
        out_attacks.append(ap)
        attack_pattern_ids.append(ap.id)

    # 2. Infer relationships
    entities = {
        "threat_actor_ids":     tier2_entities.get("threat_actor_ids", []),
        "malware_ids":          tier2_entities.get("malware_ids", []),
        "tool_ids":             tier2_entities.get("tool_ids", []),
        "attack_pattern_ids":   attack_pattern_ids,
        "vulnerability_ids":    tier1_entities.get("vulnerability_ids", []),
    }
    for rel_spec in provider.infer_relationships(entities, context=description):
        rel = builders.build_relationship(
            rel_spec["source_ref"],
            rel_spec["target_ref"],
            rel_spec["relationship_type"],
        )
        out_rels.append({
            "source_ref":        rel_spec["source_ref"],
            "target_ref":        rel_spec["target_ref"],
            "relationship_type": rel_spec["relationship_type"],
            "sdo":               rel,
        })

    # 3. Severity (Layer 2 đã làm regex CVSS + KEV; Tier 3 chỉ bổ sung)
    sev = provider.infer_severity(description)

    return {
        "attack_patterns": out_attacks,
        "relationships":   out_rels,
        "severity":        sev,
    }
