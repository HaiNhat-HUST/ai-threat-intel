"""get_provider() - chọn LLM provider qua env LLM_PROVIDER."""
from __future__ import annotations

import os

from extraction.llm.base import LLMProvider


def get_provider(name: str | None = None) -> LLMProvider:
    """
    Read env LLM_PROVIDER (default 'mock'). Override via `name` arg for tests.

    Supported: 'mock', 'claude', 'openai', 'ollama'.
    Real providers raise NotImplementedError until adapter is implemented.
    """
    if name is None:
        name = os.environ.get("LLM_PROVIDER", "mock").lower().strip()

    if name == "mock":
        from extraction.llm.mock import MockProvider
        return MockProvider()
    if name == "claude":
        from extraction.llm.claude import ClaudeProvider
        return ClaudeProvider()
    if name == "openai":
        from extraction.llm.openai_ import OpenAIProvider
        return OpenAIProvider()
    if name == "ollama":
        from extraction.llm.ollama import OllamaProvider
        return OllamaProvider()

    raise ValueError(f"Unknown LLM_PROVIDER: {name!r}. "
                     f"Use one of: mock, claude, openai, ollama.")
