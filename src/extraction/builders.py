"""
builders.py - Factory functions cho mọi STIX 2.1 SDO/SRO mà Layer 3 emit.

Deterministic UUIDv5 keyed by OBSERVABLE VALUE (not by report id),
so the same IP / hash / CVE in 3 different reports yields the SAME
Indicator/Vulnerability id - and all 3 reports' object_refs point to it.
That's how the threat-intel graph forms naturally.

Public API:
    build_indicator_ipv4(value, sources=...) -> Indicator
    build_indicator_ipv6(value, sources=...) -> Indicator
    build_indicator_domain(value, sources=...) -> Indicator
    build_indicator_url(value, sources=...) -> Indicator
    build_indicator_file_hash(hash_type, hash_value, sources=...) -> Indicator
    build_indicator_email(value, sources=...) -> Indicator
    build_indicator_btc(value, sources=...) -> Indicator
    build_vulnerability(cve_id, description=None, sources=...) -> Vulnerability
    build_relationship(src_id, target_id, type_) -> Relationship
"""
from __future__ import annotations

from datetime import datetime, timezone

from stix2 import (
    Indicator, Vulnerability, Relationship, ExternalReference, TLP_WHITE,
    Malware, ThreatActor, Tool, AttackPattern,
)

# Reuse Layer 2's deterministic-id helper and namespace
from processing.report_builder import _det_id, _det_uuid  # noqa


# ──────────────────────────────────────────────
# STIX pattern templates per observable type
# ──────────────────────────────────────────────
# Hash key spelling MUST match STIX 2.1 spec exactly:
#   file:hashes.MD5 (no quotes), file:hashes.'SHA-1', file:hashes.'SHA-256'
_HASH_KEY = {
    "md5":     "MD5",
    "sha1":    "'SHA-1'",
    "sha256":  "'SHA-256'",
    "sha512":  "'SHA-512'",
}


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stix_escape(s: str) -> str:
    """Escape backslash and single-quote for STIX pattern string literals."""
    return s.replace("\\", "\\\\").replace("'", "\\'")


def _make_indicator(stix_id: str, name: str, pattern: str,
                    indicator_types: list[str] | None = None,
                    sources: list[str] | None = None) -> Indicator:
    """Common Indicator builder: TLP marking + valid_from + optional source refs."""
    return Indicator(
        id=stix_id,
        name=name,
        pattern=pattern,
        pattern_type="stix",
        valid_from=_now_utc(),
        indicator_types=indicator_types or ["malicious-activity"],
        object_marking_refs=[TLP_WHITE.id],
        # NOTE: source attribution comes from Report.object_refs - omit ext_refs here.
        allow_custom=True,
    )


# ──────────────────────────────────────────────
# INDICATORS - one per observable VALUE
# ──────────────────────────────────────────────

def build_indicator_ipv4(value: str, sources: list[str] | None = None) -> Indicator:
    return _make_indicator(
        stix_id=_det_id("indicator", "ipv4-addr", value),
        name=f"IPv4: {value}",
        pattern=f"[ipv4-addr:value = '{_stix_escape(value)}']",
        sources=sources,
    )


def build_indicator_ipv6(value: str, sources: list[str] | None = None) -> Indicator:
    return _make_indicator(
        stix_id=_det_id("indicator", "ipv6-addr", value.lower()),
        name=f"IPv6: {value}",
        pattern=f"[ipv6-addr:value = '{_stix_escape(value)}']",
        sources=sources,
    )


def build_indicator_domain(value: str, sources: list[str] | None = None) -> Indicator:
    val = value.lower().strip(".")
    return _make_indicator(
        stix_id=_det_id("indicator", "domain-name", val),
        name=f"Domain: {val}",
        pattern=f"[domain-name:value = '{_stix_escape(val)}']",
        sources=sources,
    )


def build_indicator_url(value: str, sources: list[str] | None = None) -> Indicator:
    return _make_indicator(
        stix_id=_det_id("indicator", "url", value),
        name=f"URL: {value[:60]}",
        pattern=f"[url:value = '{_stix_escape(value)}']",
        sources=sources,
    )


def build_indicator_file_hash(hash_type: str, hash_value: str,
                              sources: list[str] | None = None) -> Indicator:
    ht = hash_type.lower().replace("-", "")
    if ht not in _HASH_KEY:
        raise ValueError(f"Unknown hash type: {hash_type!r}")
    hv = hash_value.lower()
    key = _HASH_KEY[ht]
    return _make_indicator(
        stix_id=_det_id("indicator", "file", ht, hv),
        name=f"File hash ({hash_type.upper()}): {hv[:16]}...",
        pattern=f"[file:hashes.{key} = '{_stix_escape(hv)}']",
        sources=sources,
    )


def build_indicator_email(value: str, sources: list[str] | None = None) -> Indicator:
    val = value.lower()
    return _make_indicator(
        stix_id=_det_id("indicator", "email-addr", val),
        name=f"Email: {val}",
        pattern=f"[email-addr:value = '{_stix_escape(val)}']",
        sources=sources,
    )


def build_indicator_btc(value: str, sources: list[str] | None = None) -> Indicator:
    return _make_indicator(
        stix_id=_det_id("indicator", "btc-addr", value),
        name=f"BTC: {value[:16]}...",
        # STIX 2.1 doesn't have a native btc-addr SCO; use cryptocurrency-wallet
        # via custom property. For Tier 1 simplicity we encode as URL-style.
        pattern=f"[x-bitcoin-address:value = '{_stix_escape(value)}']",
        sources=sources,
    )


# ──────────────────────────────────────────────
# VULNERABILITY (one per CVE id)
# ──────────────────────────────────────────────

def build_vulnerability(cve_id: str, description: str | None = None,
                        sources: list[str] | None = None) -> Vulnerability:
    """CVE id deterministic → cùng CVE trong N report → 1 Vulnerability SDO."""
    cve = cve_id.upper().strip()
    ext_refs = [ExternalReference(source_name="cve", external_id=cve)]
    # NOTE: not appending raw `sources` as ext_refs - ExternalReference requires
    # at least one of (description/external_id/url) per STIX 2.1. Source
    # attribution is already captured via Report.object_refs (which Report
    # mentions this Vulnerability).
    return Vulnerability(
        id=_det_id("vulnerability", "cve", cve),
        name=cve,
        description=description or cve,
        external_references=ext_refs,
        object_marking_refs=[TLP_WHITE.id],
        allow_custom=True,
    )


# ──────────────────────────────────────────────
# RELATIONSHIP
# ──────────────────────────────────────────────

def build_relationship(source_ref: str, target_ref: str,
                       relationship_type: str) -> Relationship:
    """
    Deterministic id keyed by (src, type, target) so re-extraction
    doesn't create duplicate edges.
    """
    return Relationship(
        id=_det_id("relationship", source_ref, relationship_type, target_ref),
        relationship_type=relationship_type,
        source_ref=source_ref,
        target_ref=target_ref,
        object_marking_refs=[TLP_WHITE.id],
        allow_custom=True,
    )



# ──────────────────────────────────────────────
# MALWARE / THREAT-ACTOR / TOOL (Layer 3 Tier 2)
# ──────────────────────────────────────────────

def build_malware(name: str, malware_types: list[str] | None = None,
                  is_family: bool = True,
                  aliases: list[str] | None = None,
                  description: str | None = None) -> Malware:
    """One Malware SDO per canonical name (lower-case key). is_family=True for
    families like 'LockBit'; False for specific samples."""
    canonical = name.strip()
    key = canonical.lower()
    return Malware(
        id=_det_id("malware", key),
        name=canonical,
        malware_types=malware_types or ["unknown"],
        is_family=is_family,
        aliases=aliases or None,
        description=description,
        object_marking_refs=[TLP_WHITE.id],
        allow_custom=True,
    )


def build_threat_actor(name: str,
                       threat_actor_types: list[str] | None = None,
                       aliases: list[str] | None = None,
                       description: str | None = None) -> ThreatActor:
    """One Threat-Actor SDO per canonical name (lower-case key)."""
    canonical = name.strip()
    key = canonical.lower()
    return ThreatActor(
        id=_det_id("threat-actor", key),
        name=canonical,
        threat_actor_types=threat_actor_types or ["unknown"],
        aliases=aliases or None,
        description=description,
        object_marking_refs=[TLP_WHITE.id],
        allow_custom=True,
    )


def build_tool(name: str, tool_types: list[str] | None = None,
               aliases: list[str] | None = None,
               description: str | None = None) -> Tool:
    """One Tool SDO per canonical name (lower-case key)."""
    canonical = name.strip()
    key = canonical.lower()
    return Tool(
        id=_det_id("tool", key),
        name=canonical,
        tool_types=tool_types or ["unknown"],
        aliases=aliases or None,
        description=description,
        object_marking_refs=[TLP_WHITE.id],
        allow_custom=True,
    )



def build_attack_pattern(technique_id: str, name: str,
                         tactic: str | None = None,
                         description: str | None = None) -> AttackPattern:
    """
    MITRE ATT&CK Attack-Pattern SDO.

    Deterministic id từ technique_id (T1190, T1566.001, ...) — cùng technique
    qua nhiều report luôn ra cùng SDO.

    external_references chứa source_name='mitre-attack', external_id=T-code,
    và url chính thức của attack.mitre.org.
    """
    # Build mitre URL từ T-code
    parts = technique_id.split(".")
    if len(parts) == 1:
        url = f"https://attack.mitre.org/techniques/{parts[0]}/"
    else:
        url = f"https://attack.mitre.org/techniques/{parts[0]}/{parts[1]}/"

    kill_chain = None
    if tactic:
        kill_chain = [{
            "kill_chain_name": "mitre-attack",
            "phase_name": tactic,
        }]

    return AttackPattern(
        id=_det_id("attack-pattern", "mitre-attack", technique_id.upper()),
        name=name,
        description=description,
        external_references=[
            ExternalReference(source_name="mitre-attack",
                              external_id=technique_id.upper(),
                              url=url),
        ],
        kill_chain_phases=kill_chain,
        object_marking_refs=[TLP_WHITE.id],
        allow_custom=True,
    )
