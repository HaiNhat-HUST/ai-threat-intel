"""LLMProvider Protocol - mọi provider implement đúng 3 method này."""
from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class LLMProvider(Protocol):
    """
    Provider trừu tượng để Tier 3 không phụ thuộc model cụ thể.
    Mock + real LLM đều implement Protocol này.
    """

    name: str   # vd "mock", "claude", "openai", "ollama"

    def classify_attack_pattern(
        self,
        description: str,
        hints: dict | None = None,
    ) -> list[dict]:
        """
        Map free-text description to MITRE ATT&CK techniques.

        Returns: list of {"id": "T1190", "name": "Exploit Public-Facing Application",
                          "confidence": 0..100}
        """
        ...

    def infer_relationships(
        self,
        entities: dict,
        context: str = "",
    ) -> list[dict]:
        """
        Suy luận relationship giữa các entity ID đã có.

        entities: {"threat_actor_ids": [...], "malware_ids": [...],
                   "attack_pattern_ids": [...], "vulnerability_ids": [...]}
        Returns: list of {"source_ref": ..., "target_ref": ...,
                          "relationship_type": "uses"|"targets"|"exploits"|...}
        """
        ...

    def infer_severity(self, text: str) -> str | None:
        """
        Suy luận severity từ prose khi cột không có sẵn.
        Returns one of "critical"/"high"/"medium"/"low"/"info" or None.
        """
        ...
