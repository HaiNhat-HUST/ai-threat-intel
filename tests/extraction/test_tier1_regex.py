"""Unit tests cho tier1_regex.py."""
from extraction.tier1_regex import extract_iocs


def test_cve_extracted():
    iocs = extract_iocs("Vulnerability tracked as CVE-2026-42897 in Exchange.")
    assert ("cve", "CVE-2026-42897") in iocs


def test_ipv4_defanged_refanged():
    iocs = extract_iocs("The IP 1.2.3[.]4 contacted C2 server.")
    assert ("ipv4", "1.2.3.4") in iocs


def test_hxxp_url_refanged():
    iocs = extract_iocs("payload at hxxp://evil[.]com/c2.bin downloaded")
    assert any(k == "url" and "evil.com" in v for k, v in iocs)


def test_sha256_hash():
    h = "a5e67b02b0d931c9c229c4a71289810f6a33d6e4ab5408a2f077f3fbd10a3610"
    iocs = extract_iocs(f"SHA256 of malware: {h}")
    assert ("file_hash", "sha256", h.lower()) in iocs


def test_md5_hash():
    iocs = extract_iocs("md5 = b60dd51e91841ea346b7a66aa97e9265")
    assert ("file_hash", "md5", "b60dd51e91841ea346b7a66aa97e9265") in iocs


def test_email():
    iocs = extract_iocs("Contact: attacker@bad-domain.com for ransom")
    assert ("email", "attacker@bad-domain.com") in iocs


def test_threatfox_structured_only():
    """ThreatFox row: must NOT extract win.vshell as a domain."""
    text = ("[ThreatFox] IOC\nIOC: 60.204.249.248:8084\n"
            "Type: ip:port\nMalware: win.vshell")
    iocs = extract_iocs(text, source="Abuse.ch ThreatFox")
    assert ("ipv4", "60.204.249.248") in iocs
    # No false positive
    assert not any(k == "domain" for k, *_ in iocs)


def test_malwarebazaar_structured_only():
    text = ("[MalwareBazaar] Sample\n"
            "SHA256: 0b26297bcc18752aa239926fdd62c823ec5db618b409e6467c3c42fb2d1430be\n"
            "MD5:    b60dd51e91841ea346b7a66aa97e9265\nFamily: elf")
    iocs = extract_iocs(text, source="Abuse.ch MalwareBazaar")
    kinds = {k for k, *_ in iocs}
    assert kinds == {"file_hash"}
    assert len(iocs) == 2


def test_empty_text_returns_empty():
    assert extract_iocs("") == []
    assert extract_iocs(None) == []   # type: ignore


def test_skip_obvious_non_ioc_ips():
    iocs = extract_iocs("localhost is 127.0.0.1 and broadcast is 255.255.255.255")
    assert not any(k == "ipv4" for k, *_ in iocs)
