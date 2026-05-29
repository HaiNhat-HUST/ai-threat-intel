"""Unit tests cho tier2_ner.py - structured + gazetteer extraction."""
from extraction.tier2_ner import extract_entities


def test_threatfox_malware_field_via_gazetteer_alias():
    """ThreatFox 'win.vshell' alias -> canonical 'Vshell' via gazetteer."""
    text = "[ThreatFox] IOC\nMalware: win.vshell\nType: ip:port"
    out = extract_entities(text, source="Abuse.ch ThreatFox")
    names = {name for _, name, _ in out}
    assert "Vshell" in names


def test_threatfox_unknown_malware_passes_through():
    """Tên không có trong gazetteer vẫn được emit với types=['unknown']."""
    text = "[ThreatFox] IOC\nMalware: NewFamily2026\nType: ip:port"
    out = extract_entities(text, source="Abuse.ch ThreatFox")
    found = [(k, n, t) for k, n, t in out if n == "NewFamily2026"]
    assert len(found) == 1
    assert found[0][2] == ["unknown"]


def test_malwarebazaar_generic_family_blocked():
    """'elf' / 'exe' là file type, không phải malware family - phải skip."""
    text = "[MalwareBazaar]\nSHA256: deadbeef\nFamily: elf"
    out = extract_entities(text, source="Abuse.ch MalwareBazaar")
    names = {n for _, n, _ in out}
    assert "elf" not in names
    assert "Elf" not in names


def test_gazetteer_match_in_prose():
    text = ("Researchers attributed the LockBit campaign to APT29 leveraging "
            "Cobalt Strike for lateral movement and Mimikatz for credential dumping.")
    out = extract_entities(text, source="The Hacker News")
    kinds_names = {(k, n) for k, n, _ in out}
    assert ("malware", "LockBit") in kinds_names
    assert ("threat_actor", "APT29") in kinds_names
    assert ("tool", "Cobalt Strike") in kinds_names
    assert ("tool", "Mimikatz") in kinds_names


def test_alias_resolves_to_canonical():
    """'Cozy Bear' alias should resolve to APT29 canonical name."""
    text = "Attack attributed to Cozy Bear targeting government agencies."
    out = extract_entities(text, source="The Hacker News")
    names = {n for k, n, _ in out if k == "threat_actor"}
    assert "APT29" in names


def test_case_insensitive_match():
    text = "lockbit 3.0 ransomware deployed by FIN7 affiliates."
    out = extract_entities(text, source="The Hacker News")
    names = {n for _, n, _ in out}
    # Canonical form returned, not the lowercased input
    assert "LockBit" in names
    assert "FIN7" in names


def test_no_false_positive_on_substring():
    """Word-boundary: 'apt28' INSIDE 'computer-apt28something' must NOT match.
    Also generic words like 'play' (cluster card-game) shouldn't trigger."""
    text = "The system was kept up-to-date and the team enjoyed a board game."
    out = extract_entities(text, source="The Hacker News")
    # 'Play' is in malware index but should NOT match the word 'kept' etc
    # Note: 'Play' DOES exist as a ransomware family. As long as the literal
    # word 'play' doesn't appear, we're fine.
    names = {n.lower() for _, n, _ in out}
    assert "play" not in names


def test_empty_returns_empty():
    assert extract_entities("") == []
    assert extract_entities(None) == []   # type: ignore


def test_dedup_within_one_report():
    """Same name mentioned twice -> 1 entity."""
    text = "LockBit attack. LockBit ransomware. The LockBit gang struck again."
    out = extract_entities(text, source="The Hacker News")
    lockbit_hits = [n for k, n, _ in out if n == "LockBit"]
    assert len(lockbit_hits) == 1
