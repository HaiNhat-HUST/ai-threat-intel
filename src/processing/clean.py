"""
clean.py - Strip HTML/markdown, normalize timestamps & severity, detect language,
            infer missing severity from content patterns.

All functions here are pure - easy to unit-test.

Public API:
    clean_text(raw: str) -> str
    normalize_severity(s: str | None) -> str | None
    infer_severity_from_content(source: str, raw: str) -> str | None
    to_utc(dt: datetime) -> datetime
    to_stix_timestamp(dt: datetime) -> str
    detect_language(text: str) -> str   # ISO 639-1 lowercase, e.g. "en", "vi"
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from functools import lru_cache

from bs4 import BeautifulSoup
from lingua import Language, LanguageDetectorBuilder

# ──────────────────────────────────────────────
# HTML / MARKDOWN STRIP
# ──────────────────────────────────────────────

_HTML_TAG_RE = re.compile(r"<[^>]+>")

# Light markdown stripper - giữ NỘI DUNG code blocks (chứa IOC),
# chỉ bỏ KÝ HIỆU markdown.
_MD_FENCE_OPEN  = re.compile(r"```[a-zA-Z0-9_+\-]*\n?")
_MD_FENCE_CLOSE = re.compile(r"\n?```")
_MD_HEADER      = re.compile(r"^\s*#{1,6}\s*", re.MULTILINE)
_MD_BOLD        = re.compile(r"\*\*([^*\n]+)\*\*")
_MD_ITAL        = re.compile(r"(?<!\*)\*([^*\n]+)\*(?!\*)")
_MD_INLINE_CODE = re.compile(r"`([^`\n]+)`")
_MD_LINK        = re.compile(r"\[([^\]]+)\]\([^)]+\)")
_MD_BULLET      = re.compile(r"^\s*[-*+]\s+", re.MULTILINE)

_WS_RUN  = re.compile(r"[ \t]+")
_BLANKS  = re.compile(r"\n{3,}")


def _looks_like_html(s: str) -> bool:
    return bool(_HTML_TAG_RE.search(s))


def strip_html(s: str) -> str:
    if not _looks_like_html(s):
        return s
    return BeautifulSoup(s, "html.parser").get_text(separator=" ")


def strip_markdown(s: str) -> str:
    s = _MD_FENCE_OPEN.sub("", s)
    s = _MD_FENCE_CLOSE.sub("", s)
    s = _MD_HEADER.sub("", s)
    s = _MD_BOLD.sub(r"\1", s)
    s = _MD_ITAL.sub(r"\1", s)
    s = _MD_INLINE_CODE.sub(r"\1", s)
    s = _MD_LINK.sub(r"\1", s)
    s = _MD_BULLET.sub("", s)
    return s


def clean_text(raw: str) -> str:
    """Strip HTML + markdown, normalize whitespace. Preserves IOC content."""
    if not raw:
        return ""
    s = strip_html(raw)
    s = strip_markdown(s)
    s = _WS_RUN.sub(" ", s)
    s = _BLANKS.sub("\n\n", s)
    return s.strip()


# ──────────────────────────────────────────────
# SEVERITY NORMALIZATION
# ──────────────────────────────────────────────

_SEV_MAP = {
    "critical":      "critical",
    "crit":          "critical",
    "high":          "high",
    "important":     "high",
    "medium":        "medium",
    "med":           "medium",
    "moderate":      "medium",
    "low":           "low",
    "info":          "info",
    "informational": "info",
    "none":          None,
    "unknown":       None,
}


def normalize_severity(s: str | None) -> str | None:
    """CRITICAL/Critical/Crit/... → critical. None/blank → None."""
    if s is None:
        return None
    key = s.strip().lower()
    if not key:
        return None
    return _SEV_MAP.get(key, None)


# ──────────────────────────────────────────────
# SEVERITY INFERENCE from raw content
# ──────────────────────────────────────────────

# Match patterns like "CVSS:3.1/AV:N/AC:L/.../A:H 9.8", "Base Score: 7.5",
# "CVSS Score: 8.1", "score: 6.3"
_CVSS_SCORE_RE = re.compile(
    r"(?:base[\s_-]?score|cvss[\s_-]?(?:v?\d\.?\d?[\s_-]?)?score|score)\s*[:=]\s*(\d{1,2}\.?\d?)",
    re.IGNORECASE,
)
# Fallback: trailing score after CVSS vector like ".../A:H 9.8" or "...A:H/E:F 7.5"
_CVSS_TAIL_RE = re.compile(r"CVSS[:\s][^\s]*?(\d{1,2}\.\d)\b", re.IGNORECASE)


def _score_to_severity(score: float) -> str | None:
    """CVSS v3 official ranges."""
    if score >= 9.0:    return "critical"
    if score >= 7.0:    return "high"
    if score >= 4.0:    return "medium"
    if score >  0.0:    return "low"
    if score == 0.0:    return "info"
    return None


def infer_severity_from_content(source: str, raw_content: str) -> str | None:
    """
    Suy luận severity khi cột severity là None (32/90 row trong data hiện tại).
    Quy tắc:
      1. CISA KEV → 'critical' (theo định nghĩa: đang bị exploit thực tế).
      2. Regex CVSS score trong raw_content → map theo thang chính thức.
      3. Không match được → trả None (Layer 3 LLM sẽ xử lý).
    """
    # Rule 1: CISA KEV
    if source and source.strip().lower().startswith("cisa kev"):
        return "critical"

    if not raw_content:
        return None

    # Rule 2: CVSS score
    for pat in (_CVSS_SCORE_RE, _CVSS_TAIL_RE):
        m = pat.search(raw_content)
        if m:
            try:
                return _score_to_severity(float(m.group(1)))
            except (ValueError, IndexError):
                continue

    return None


# ──────────────────────────────────────────────
# TIMESTAMP → UTC
# ──────────────────────────────────────────────

def to_utc(dt: datetime) -> datetime:
    """Bảo đảm datetime có tzinfo = UTC. Naive datetime giả định đã là UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def to_stix_timestamp(dt: datetime) -> str:
    """Format datetime → STIX 2.1 timestamp (RFC 3339, UTC, suffix Z)."""
    return to_utc(dt).strftime("%Y-%m-%dT%H:%M:%SZ")


# ──────────────────────────────────────────────
# LANGUAGE DETECTION
# ──────────────────────────────────────────────

_LANGS = [
    Language.ENGLISH, Language.VIETNAMESE, Language.CHINESE,
    Language.RUSSIAN, Language.JAPANESE,   Language.GERMAN,
    Language.FRENCH,  Language.SPANISH,    Language.KOREAN,
]


@lru_cache(maxsize=1)
def _detector():
    return LanguageDetectorBuilder.from_languages(*_LANGS).build()


def detect_language(text: str) -> str:
    """Detect ngôn ngữ → ISO 639-1 lowercase. Fallback 'en' nếu detect None."""
    if not text or not text.strip():
        return "en"
    sample = text[:2000]
    lang = _detector().detect_language_of(sample)
    if lang is None:
        return "en"
    return lang.iso_code_639_1.name.lower()
