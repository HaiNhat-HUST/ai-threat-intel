"""
extraction/llm/ - Provider-agnostic LLM interface for Layer 3 Tier 3.

Mọi LLM call đi qua LLMProvider Protocol. Mặc định dùng MockProvider
(rule-based, deterministic). Khi đội chốt được model thật, viết adapter
class trong claude.py / openai.py / ollama.py rồi đổi env LLM_PROVIDER.

    from extraction.llm.factory import get_provider
    provider = get_provider()            # đọc env LLM_PROVIDER (default 'mock')
    techs    = provider.classify_attack_pattern(description, hints=...)
    rels     = provider.infer_relationships(entities, context)
    sev      = provider.infer_severity(text)
"""
from extraction.llm.base import LLMProvider
from extraction.llm.factory import get_provider

__all__ = ["LLMProvider", "get_provider"]
