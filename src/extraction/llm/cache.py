"""Prompt cache để re-run không gọi LLM lại (tiết kiệm token + deterministic dev)."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

_CACHE_DIR = Path(os.environ.get(
    "LLM_CACHE_DIR",
    Path.home() / ".cache" / "ai-threat-intel" / "llm",
))


def _key(provider: str, method: str, payload: Any) -> Path:
    blob = json.dumps([provider, method, payload], sort_keys=True, default=str)
    digest = hashlib.sha256(blob.encode()).hexdigest()[:24]
    return _CACHE_DIR / f"{provider}_{method}_{digest}.json"


def get(provider: str, method: str, payload: Any):
    path = _key(provider, method, payload)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def put(provider: str, method: str, payload: Any, value: Any) -> None:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = _key(provider, method, payload)
    path.write_text(json.dumps(value, default=str))
