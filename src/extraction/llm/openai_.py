"""
OpenAIProvider stub - implement khi đội chốt dùng OpenAI GPT.

Kế hoạch:
    pip install openai
    export OPENAI_API_KEY=...
    export LLM_PROVIDER=openai
    export OPENAI_MODEL=gpt-4o   # default
"""
from __future__ import annotations


class OpenAIProvider:
    name = "openai"

    def __init__(self, model: str = "gpt-4o"):
        self.model = model
        raise NotImplementedError(
            "OpenAIProvider stub. To activate: pip install openai, set "
            "OPENAI_API_KEY, implement the three methods using the OpenAI SDK."
        )

    def classify_attack_pattern(self, description: str, hints=None): raise NotImplementedError
    def infer_relationships(self, entities, context: str = ""):       raise NotImplementedError
    def infer_severity(self, text: str):                              raise NotImplementedError
