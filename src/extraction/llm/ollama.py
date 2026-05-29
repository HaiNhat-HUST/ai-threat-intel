"""
OllamaProvider stub - implement khi đội chọn local LLM (Llama / Qwen / Mistral).

Kế hoạch:
    Cài ollama (https://ollama.com) → ollama pull llama3.1:8b
    export LLM_PROVIDER=ollama
    export OLLAMA_MODEL=llama3.1:8b
    export OLLAMA_HOST=http://localhost:11434
"""
from __future__ import annotations


class OllamaProvider:
    name = "ollama"

    def __init__(self, model: str = "llama3.1:8b",
                 host: str = "http://localhost:11434"):
        self.model = model
        self.host = host
        raise NotImplementedError(
            "OllamaProvider stub. To activate: install ollama, pull model, "
            "and implement methods using httpx POST {host}/api/generate."
        )

    def classify_attack_pattern(self, description: str, hints=None): raise NotImplementedError
    def infer_relationships(self, entities, context: str = ""):       raise NotImplementedError
    def infer_severity(self, text: str):                              raise NotImplementedError
