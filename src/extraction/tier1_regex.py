"""
tier1_regex.py - Layer 3 Tier 1: regex / iocextract-based IOC extraction.

Pure function: extract_iocs(text, source=None) -> list of (kind, *values).
No DB, no STIX. Builders consume this output to make SDOs.

Kinds returned:
    ("cve",       cve_id)
    ("ipv4",      address)
    ("ipv6",      address)
    ("domain",    domain_name)
    ("url",       url)
    ("file_hash", hash_type, hash_value)   hash_type in {md5, sha1, sha256, sha512}
    ("email",     email_address)
    ("btc",       btc_address)

Structured-source parsing:
    Khi `source` được truyền vào, ta thêm parser riêng cho ThreatFox
    (`IOC: x.x.x.x:port`) và MalwareBazaar (`SHA256: ...`) - bám sát
    format đã biết của Hùng, không phụ thuộc iocextract regex tổng quát.
"""
from __future__ import annotations

import re

import iocextract

# ──────────────────────────────────────────────
# CUSTOM REGEX (iocextract không bắt CVE & vài thứ nữa)
# ──────────────────────────────────────────────

_CVE_RE = re.compile(r"CVE[-\s]?\d{4}[-\s]?\d{4,7}", re.IGNORECASE)

# Domain (FQDN): có ít nhất 1 dấu chấm, TLD 2-24 ký tự chữ cái.
# Loại trừ chuỗi toàn số (= IP) bằng negative lookahead.
_DOMAIN_RE = re.compile(
    r"\b(?!\d+\.)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,24}\b"
)

# Bitcoin address (legacy + bech32, đơn giản hoá).
_BTC_RE = re.compile(r"\b(?:bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z0-9]{25,34})\b")

# Structured fields
_TF_IOC_LINE = re.compile(r"^\s*IOC\s*[:=]\s*([^\s\n]+)", re.MULTILINE | re.IGNORECASE)
_MB_HASH_LINE = re.compile(
    r"^\s*(MD5|SHA[\s-]?1|SHA[\s-]?256|SHA[\s-]?512)\s*[:=]\s*([a-fA-F0-9]+)\b",
    re.MULTILINE | re.IGNORECASE,
)

# Defang the text first - iocextract has refang_* helpers
# but we apply manually so all extractors see consistent input.
def _refang(text: str) -> str:
    if not text:
        return ""
    # common defang patterns:  hxxp -> http, [.] -> .,  (.) -> .,  [://] -> ://, [/] -> /
    s = text
    s = re.sub(r"hxxp(s?)://", r"http\1://", s, flags=re.IGNORECASE)
    s = s.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    s = s.replace("[://]", "://").replace("[/]", "/")
    s = s.replace("[@]", "@").replace("(@)", "@")
    return s


# Hash type normalization for the MalwareBazaar regex group
def _norm_hash_type(raw: str) -> str:
    s = raw.lower().replace(" ", "").replace("-", "")
    return s  # md5 / sha1 / sha256 / sha512


def _ipv4_to_skip() -> set[str]:
    """Exclude obvious non-IOC IPs to reduce false positives."""
    return {"0.0.0.0", "127.0.0.1", "255.255.255.255"}


_SKIP_DOMAINS = {
    # Common false positives - documentation/spec / e-mail-as-domain artifacts
    "example.com", "example.org", "example.net",
    "domain.com", "localhost",
}


def _parse_structured(text: str, source: str | None) -> list[tuple]:
    """ThreatFox / MalwareBazaar / KEV - cấu trúc rõ ràng, không cần iocextract."""
    found = []
    if not source:
        return found
    s = source.strip().lower()

    if "threatfox" in s:
        # "IOC: 60.204.249.248:8084"  →  IPv4
        # "IOC: example-bad.com"      →  domain
        # "IOC: https://example.com"  →  url
        for m in _TF_IOC_LINE.finditer(text):
            val = m.group(1).strip()
            # strip :port for ip:port format
            host = val.split(":")[0] if val.count(":") == 1 and not val.startswith("http") else val
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
                found.append(("ipv4", host))
            elif host.startswith("http"):
                found.append(("url", val))
            elif "." in host:
                found.append(("domain", host.lower()))

    if "malwarebazaar" in s:
        for m in _MB_HASH_LINE.finditer(text):
            ht = _norm_hash_type(m.group(1))
            hv = m.group(2).lower()
            # validate length per type
            if (ht == "md5"    and len(hv) == 32) \
            or (ht == "sha1"   and len(hv) == 40) \
            or (ht == "sha256" and len(hv) == 64) \
            or (ht == "sha512" and len(hv) == 128):
                found.append(("file_hash", ht, hv))

    return found


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

_STRUCTURED_ONLY_SOURCES = {"abuse.ch threatfox", "abuse.ch malwarebazaar"}


def extract_iocs(text: str, source: str | None = None) -> list[tuple]:
    """
    Extract all Tier-1 IOCs from `text` (clean Report description).
    Returns deduplicated list of tuples ready for the builders module.

    For "structured-only" sources (ThreatFox, MalwareBazaar) we trust the
    explicit IOC fields and skip the generic regex (avoids false positives
    like treating malware family names "win.vshell" as a domain).
    """
    if not text:
        return []

    found: set[tuple] = set()

    # Structured-only fast path
    src = (source or "").strip().lower()
    if src in _STRUCTURED_ONLY_SOURCES:
        for item in _parse_structured(text, source):
            found.add(item)
        return sorted(found)

    refanged = _refang(text)

    # CVE
    for m in _CVE_RE.finditer(refanged):
        # Normalize "CVE 2026 8723" / "CVE-2026-8723" / "CVE2026-8723"
        normalized = re.sub(r"[\s_]", "-", m.group()).upper()
        normalized = re.sub(r"-+", "-", normalized)
        # Re-check the canonical form
        cm = re.match(r"CVE-(\d{4})-(\d{4,7})", normalized)
        if cm:
            found.add(("cve", f"CVE-{cm.group(1)}-{cm.group(2)}"))

    # IPv4 (refanged already)
    for ip in iocextract.extract_ipv4s(refanged, refang=True):
        ip = ip.strip().strip(".")
        if ip and ip not in _ipv4_to_skip():
            found.add(("ipv4", ip))

    # IPv6
    for ip in iocextract.extract_ipv6s(refanged):
        found.add(("ipv6", ip.strip()))

    # URLs
    for url in iocextract.extract_urls(refanged, refang=True, strip=True):
        u = url.strip()
        if u:
            found.add(("url", u))

    # Domains via custom regex (iocextract only does URLs)
    for m in _DOMAIN_RE.finditer(refanged):
        d = m.group().lower().strip(".")
        if d in _SKIP_DOMAINS:
            continue
        # avoid duplicate domains that are part of an extracted URL
        if any(d in url for kind, url in found if kind == "url"):
            continue
        found.add(("domain", d))

    # File hashes
    for h in iocextract.extract_md5_hashes(refanged):
        found.add(("file_hash", "md5", h.lower()))
    for h in iocextract.extract_sha1_hashes(refanged):
        found.add(("file_hash", "sha1", h.lower()))
    for h in iocextract.extract_sha256_hashes(refanged):
        found.add(("file_hash", "sha256", h.lower()))
    for h in iocextract.extract_sha512_hashes(refanged):
        found.add(("file_hash", "sha512", h.lower()))

    # Emails
    for e in iocextract.extract_emails(refanged, refang=True):
        found.add(("email", e.lower().strip()))

    # Bitcoin
    for m in _BTC_RE.finditer(refanged):
        found.add(("btc", m.group()))

    # Structured source-specific extras
    for item in _parse_structured(text, source):
        found.add(item)

    return sorted(found)
