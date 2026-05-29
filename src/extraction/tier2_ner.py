"""
tier2_ner.py - Layer 3 Tier 2: structured + gazetteer-based entity extraction.

Tier 2 rút ra MALWARE, THREAT-ACTOR, TOOL theo hai cách:
    1. Structured parsing - cho ThreatFox (`Malware: win.vshell`) và
       MalwareBazaar (`Family: <name>`). Đáng tin cậy vì format cố định.
    2. Gazetteer match - exact word-boundary search trong description với
       danh sách ~150 names trong gazetteer.py. Case-insensitive, không cần
       LLM/transformer.

Lý do KHÔNG dùng spaCy/SecureBERT trong Tier 2 baseline:
    - Model nặng (300MB - 5GB), tải lâu, không phù hợp sandbox dev.
    - Gazetteer recall đủ cao cho data hiện có (CTI feeds đề cập tên hữu hạn).
    - Có thể add spaCy như enhancement không-bắt-buộc sau này.

Public API:
    extract_entities(text, source) -> list of (kind, canonical_name, types)
       kind in {"malware", "threat_actor", "tool"}
       types: list[str], vd. ["ransomware"] / ["nation-state"]
"""
from __future__ import annotations

import re
from typing import Iterable

from extraction.gazetteer import (
    MALWARE_INDEX, THREAT_ACTOR_INDEX, TOOL_INDEX,
    GENERIC_FAMILY_BLOCKLIST,
)


# Structured field patterns
_TF_MALWARE = re.compile(r"^\s*Malware\s*[:=]\s*([^\n]+)", re.MULTILINE | re.IGNORECASE)
_MB_FAMILY  = re.compile(r"^\s*Family\s*[:=]\s*([^\n]+)",  re.MULTILINE | re.IGNORECASE)


_PLATFORM_PREFIX_RE = __import__("re").compile(
    r"^(?:win|elf|osx|apk|ios|js|vbs|bat|ps1|py|html|macho)\.",
    flags=__import__("re").IGNORECASE,
)


def _strip_to_name(s: str) -> str:
    """Lấy phần tên hữu ích từ field structured. 'win.vshell' → 'win.vshell'."""
    return s.strip().split()[0] if s.strip() else ""


def _strip_platform_prefix(name: str) -> str:
    """ThreatFox naming convention: '<platform>.<family>' → '<family>'.
    Vd 'win.vshell' → 'vshell',  'elf.mirai' → 'mirai'."""
    return _PLATFORM_PREFIX_RE.sub("", name)


def _gazetteer_matches(text: str, index: dict) -> Iterable[tuple]:
    """
    Tìm từ trong text khớp key trong index. Word-boundary để tránh
    'apt28' match trong 'capture/apture'. Case-insensitive.
    """
    if not text:
        return
    lower = text.lower()
    for key, (canonical, types) in index.items():
        # Use word boundary regex; escape special chars in key
        pat = r"(?<![\w.])" + re.escape(key) + r"(?![\w.])"
        if re.search(pat, lower):
            yield (canonical, types)


def _structured_malware(text: str, source: str | None) -> list[tuple[str, list[str]]]:
    """ThreatFox / MalwareBazaar structured 'Malware:' / 'Family:' fields."""
    found = []
    src = (source or "").strip().lower()

    if "threatfox" in src:
        for m in _TF_MALWARE.finditer(text):
            name = _strip_to_name(m.group(1))
            if not name or name.lower() in GENERIC_FAMILY_BLOCKLIST:
                continue
            # Try gazetteer with raw name first, then with platform prefix stripped
            for lookup in (name.lower(), _strip_platform_prefix(name).lower()):
                gz = MALWARE_INDEX.get(lookup)
                if gz:
                    found.append((gz[0], gz[1]))
                    break
            else:
                # Unknown name → emit with stripped form to be cleaner
                clean = _strip_platform_prefix(name)
                found.append((clean.title() if clean.islower() else clean, ["unknown"]))

    if "malwarebazaar" in src:
        for m in _MB_FAMILY.finditer(text):
            name = _strip_to_name(m.group(1))
            if not name or name.lower() in GENERIC_FAMILY_BLOCKLIST:
                continue
            for lookup in (name.lower(), _strip_platform_prefix(name).lower()):
                gz = MALWARE_INDEX.get(lookup)
                if gz:
                    found.append((gz[0], gz[1]))
                    break
            else:
                clean = _strip_platform_prefix(name)
                found.append((clean.title() if clean.islower() else clean, ["unknown"]))

    return found


def extract_entities(text: str, source: str | None = None) -> list[tuple]:
    """
    Return list of (kind, canonical_name, types) deduplicated.
    """
    if not text:
        return []

    # (kind, lower_key) -> (canonical_name, types)  — preserves original casing
    out: dict[tuple[str, str], tuple[str, list[str]]] = {}
    src = (source or "").strip().lower()
    is_structured = ("threatfox" in src) or ("malwarebazaar" in src)

    # 1. Structured (high-confidence) - chỉ áp dụng cho ThreatFox/MalwareBazaar
    for canonical, types in _structured_malware(text, source):
        out[("malware", canonical.lower())] = (canonical, types)

    # 2. Gazetteer match - SKIP cho structured sources để tránh false positive
    # (vd "Reporter: anonymous" sẽ match Anonymous hacktivist group).
    if not is_structured:
        for canonical, types in _gazetteer_matches(text, MALWARE_INDEX):
            out.setdefault(("malware", canonical.lower()), (canonical, types))
        for canonical, types in _gazetteer_matches(text, THREAT_ACTOR_INDEX):
            out.setdefault(("threat_actor", canonical.lower()), (canonical, types))
        for canonical, types in _gazetteer_matches(text, TOOL_INDEX):
            out.setdefault(("tool", canonical.lower()), (canonical, types))

    final = [(kind, canon, types) for (kind, _), (canon, types) in out.items()]
    return sorted(final, key=lambda t: (t[0], t[1].lower()))
