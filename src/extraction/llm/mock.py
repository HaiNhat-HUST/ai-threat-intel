"""
MockProvider - deterministic rule-based "LLM" cho dev + tests.

KHÔNG phải toy. Dùng:
    - Gazetteer match keywords ATT&CK trong description → classify_attack_pattern
    - Type-based rules cho infer_relationships (actor uses malware,
      malware uses attack-pattern, attack-pattern targets vulnerability)
    - Keyword-based severity inference

Coverage thực tế: ~50-60% case. Đủ để Tier 3 chạy end-to-end và demo.
Real LLM provider giải quyết phần còn lại (ngữ cảnh phức tạp, edge case).
"""
from __future__ import annotations

import re

from extraction.attack_kb import KEYWORD_INDEX


class MockProvider:
    name = "mock"

    # ── classify_attack_pattern ─────────────────────────
    def classify_attack_pattern(
        self, description: str, hints: dict | None = None,
    ) -> list[dict]:
        if not description:
            return []
        text = description.lower()
        seen: dict[str, dict] = {}     # tid -> entry

        for keyword, entries in KEYWORD_INDEX.items():
            # word-boundary on alphanumeric chars
            pat = r"(?<![\w])" + re.escape(keyword) + r"(?![\w])"
            if re.search(pat, text):
                for tid, name, tactic in entries:
                    if tid not in seen:
                        seen[tid] = {
                            "id": tid,
                            "name": name,
                            "tactic": tactic,
                            "confidence": 70,
                        }
        return sorted(seen.values(), key=lambda d: d["id"])

    # ── infer_relationships ─────────────────────────────
    def infer_relationships(
        self, entities: dict, context: str = "",
    ) -> list[dict]:
        """
        Rule-based: trong cùng report, emit các quan hệ chuẩn theo type pairs.
        Real LLM sẽ làm tốt hơn bằng cách đọc context cụ thể.
        """
        actors = entities.get("threat_actor_ids", [])
        malwares = entities.get("malware_ids", [])
        attacks = entities.get("attack_pattern_ids", [])
        vulns = entities.get("vulnerability_ids", [])
        tools = entities.get("tool_ids", [])

        rels: list[dict] = []

        # Threat-actor USES malware
        for a in actors:
            for m in malwares:
                rels.append({"source_ref": a, "target_ref": m,
                             "relationship_type": "uses"})

        # Threat-actor USES tool
        for a in actors:
            for t in tools:
                rels.append({"source_ref": a, "target_ref": t,
                             "relationship_type": "uses"})

        # Malware USES attack-pattern
        for m in malwares:
            for ap in attacks:
                rels.append({"source_ref": m, "target_ref": ap,
                             "relationship_type": "uses"})

        # Attack-pattern TARGETS vulnerability
        for ap in attacks:
            for v in vulns:
                rels.append({"source_ref": ap, "target_ref": v,
                             "relationship_type": "targets"})

        return rels

    # ── infer_severity ──────────────────────────────────
    _CRITICAL_KW = re.compile(
        r"\b(critical|catastrophic|severe|wormable|pre[-\s]?auth(?:enticated)?\s+rce|"
        r"actively\s+exploited|zero[-\s]?day in the wild)\b", re.IGNORECASE)
    _HIGH_KW = re.compile(
        r"\b(high\s+severity|high\s+impact|important|rce|"
        r"remote\s+code\s+execution|privilege\s+escalation)\b", re.IGNORECASE)
    _LOW_KW = re.compile(
        r"\b(low\s+severity|low\s+impact|minor|informational)\b",
        re.IGNORECASE)

    def infer_severity(self, text: str) -> str | None:
        if not text:
            return None
        if self._CRITICAL_KW.search(text):
            return "critical"
        if self._HIGH_KW.search(text):
            return "high"
        if self._LOW_KW.search(text):
            return "low"
        return None
