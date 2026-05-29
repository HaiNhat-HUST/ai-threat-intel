"""
gazetteer.py - Curated lists of known cyber-threat entity names for Tier 2.

Mỗi entry: canonical display name + optional aliases + STIX type info.
Khoá lookup là LOWERCASE của canonical name.

Sources of names:
- MITRE ATT&CK group/software catalog
- Public CTI vendor reports (Mandiant, Microsoft, CrowdStrike, ESET, Kaspersky)
- abuse.ch ThreatFox common malware tags

Đây là Tier-2 baseline (~150 entries). Mở rộng dần khi gặp data mới.
"""
from __future__ import annotations

# (canonical_name, malware_types, aliases)
MALWARE: list[tuple[str, list[str], list[str]]] = [
    # Ransomware
    ("LockBit",       ["ransomware"], ["LockBit 2.0", "LockBit 3.0", "LockBit Black"]),
    ("BlackCat",      ["ransomware"], ["ALPHV", "Noberus"]),
    ("Conti",         ["ransomware"], []),
    ("REvil",         ["ransomware"], ["Sodinokibi"]),
    ("Ryuk",          ["ransomware"], []),
    ("Babuk",         ["ransomware"], []),
    ("Clop",          ["ransomware"], ["Cl0p"]),
    ("Hive",          ["ransomware"], []),
    ("Black Basta",   ["ransomware"], []),
    ("Royal",         ["ransomware"], []),
    ("Akira",         ["ransomware"], []),
    ("Play",          ["ransomware"], []),
    ("Medusa",        ["ransomware"], []),
    ("WannaCry",      ["ransomware", "worm"], []),
    ("NotPetya",      ["ransomware", "wiper"], []),
    ("BadRabbit",     ["ransomware"], []),

    # Loaders / trojans / banker
    ("Emotet",        ["trojan", "downloader"], []),
    ("TrickBot",      ["trojan", "banker"], []),
    ("IcedID",        ["trojan", "downloader"], ["BokBot"]),
    ("Qakbot",        ["trojan", "banker"], ["Qbot"]),
    ("Dridex",        ["trojan", "banker"], []),
    ("BazarLoader",   ["downloader"], ["BazaLoader"]),
    ("Bumblebee",     ["downloader"], []),
    ("SocGholish",    ["downloader"], []),
    ("Pikabot",       ["downloader"], []),

    # Info-stealers
    ("RedLine",       ["stealer"], ["RedLine Stealer"]),
    ("Raccoon",       ["stealer"], ["Raccoon Stealer"]),
    ("Vidar",         ["stealer"], []),
    ("Lumma",         ["stealer"], ["LummaC2"]),
    ("AgentTesla",    ["stealer", "keylogger"], []),
    ("FormBook",      ["stealer"], []),
    ("StealC",        ["stealer"], []),
    ("Mars Stealer",  ["stealer"], []),

    # RATs
    ("NjRAT",         ["remote-access-trojan"], ["Bladabindi"]),
    ("AsyncRAT",      ["remote-access-trojan"], []),
    ("NanoCore",      ["remote-access-trojan"], []),
    ("Remcos",        ["remote-access-trojan"], []),
    ("QuasarRAT",     ["remote-access-trojan"], ["Quasar"]),
    ("Gh0stRAT",      ["remote-access-trojan"], ["Gh0st"]),
    ("DarkComet",     ["remote-access-trojan"], []),
    ("PlugX",         ["remote-access-trojan"], []),
    ("ShadowPad",     ["backdoor"], []),
    ("KEYPLUG",       ["backdoor"], []),
    ("Winnti",        ["backdoor"], []),

    # Cryptominers
    ("XMRig",         ["resource-exploitation"], []),

    # Mobile
    ("Pegasus",       ["spyware"], []),
    ("Joker",         ["mobile-malware"], []),
    ("FluBot",        ["mobile-malware"], []),
    ("Anubis",        ["mobile-malware", "banker"], []),

    # Abuse.ch ThreatFox common tags
    ("Vshell",        ["backdoor"], ["win.vshell"]),
    ("Mythic",        ["backdoor"], []),
    ("Sliver",        ["backdoor"], []),
    ("Havoc",         ["backdoor"], []),

    # Notable historical
    ("Stuxnet",       ["worm"], []),
    ("Mirai",         ["botnet"], []),
    ("Conficker",     ["worm"], []),
]

# (canonical_name, actor_types, aliases)
THREAT_ACTORS: list[tuple[str, list[str], list[str]]] = [
    # APT groups (state-sponsored)
    ("APT1",          ["nation-state"], ["Comment Crew", "PLA Unit 61398"]),
    ("APT3",          ["nation-state"], ["Gothic Panda"]),
    ("APT10",         ["nation-state"], ["Stone Panda", "MenuPass"]),
    ("APT28",         ["nation-state"], ["Fancy Bear", "Sofacy", "STRONTIUM"]),
    ("APT29",         ["nation-state"], ["Cozy Bear", "Nobelium", "Midnight Blizzard"]),
    ("APT33",         ["nation-state"], ["Elfin"]),
    ("APT34",         ["nation-state"], ["OilRig"]),
    ("APT37",         ["nation-state"], ["Reaper", "ScarCruft"]),
    ("APT38",         ["nation-state"], []),
    ("APT41",         ["nation-state", "criminal"], ["Barium", "Wicked Panda"]),
    ("Lazarus",       ["nation-state"], ["Lazarus Group", "Hidden Cobra"]),
    ("Kimsuky",       ["nation-state"], []),
    ("Sandworm",      ["nation-state"], ["Voodoo Bear"]),
    ("Turla",         ["nation-state"], ["Snake", "Venomous Bear"]),
    ("Equation Group",["nation-state"], []),
    ("Charming Kitten",["nation-state"], ["Phosphorus", "Mint Sandstorm"]),
    ("MuddyWater",    ["nation-state"], []),
    ("Volt Typhoon",  ["nation-state"], []),

    # Cybercrime
    ("FIN7",          ["criminal"], ["Carbanak", "Carbon Spider"]),
    ("FIN8",          ["criminal"], []),
    ("TA505",         ["criminal"], []),
    ("TA551",         ["criminal"], ["Shathak"]),
    ("Wizard Spider", ["criminal"], []),
    ("Indrik Spider", ["criminal"], ["Evil Corp"]),
    ("Scattered Spider",["criminal"], ["UNC3944"]),
    ("Lapsus$",       ["criminal", "hacker"], ["DEV-0537"]),
    ("TeamPCP",       ["criminal"], []),
    ("Magecart",      ["criminal"], []),
    ("Cl0p",          ["criminal"], []),
    ("ALPHV",         ["criminal"], []),

    # Hacktivists / others
    ("Anonymous",     ["hacktivist"], []),
    ("KillNet",       ["hacktivist"], []),
]

# (canonical_name, tool_types, aliases)
TOOLS: list[tuple[str, list[str], list[str]]] = [
    # Offensive / C2 frameworks
    ("Cobalt Strike", ["exploitation"], []),
    ("Brute Ratel",   ["exploitation"], ["BRC4"]),
    ("Metasploit",    ["exploitation"], []),
    ("Empire",        ["exploitation"], ["PowerShell Empire"]),
    ("Covenant",      ["exploitation"], []),
    ("Sliver",        ["exploitation"], []),  # also malware in ThreatFox tags
    ("Mythic",        ["exploitation"], []),
    ("Havoc",         ["exploitation"], []),

    # Credential / lateral movement
    ("Mimikatz",      ["credential-exploitation"], []),
    ("LaZagne",       ["credential-exploitation"], []),
    ("ProcDump",      ["credential-exploitation"], []),
    ("PsExec",        ["remote-access"], []),
    ("Impacket",      ["remote-access"], []),
    ("BloodHound",    ["information-gathering"], []),
    ("SharpHound",    ["information-gathering"], []),

    # Scanners / recon
    ("nmap",          ["network-scanner"], []),
    ("masscan",       ["network-scanner"], []),
    ("Nessus",        ["vulnerability-scanner"], []),

    # Often-abused legit
    ("AnyDesk",       ["remote-access"], []),
    ("TeamViewer",    ["remote-access"], []),
    ("Rclone",        ["data-exfiltration"], []),
    ("MEGAsync",      ["data-exfiltration"], []),
    ("ngrok",         ["remote-access"], []),
]


# ──────────────────────────────────────────────
# DERIVED LOOKUPS (for fast matching)
# ──────────────────────────────────────────────

def _index(entries: list[tuple[str, list[str], list[str]]]) -> dict[str, tuple]:
    """Build lower-case key -> (canonical_name, types_list) lookup,
    including aliases as separate keys pointing to the same canonical."""
    idx = {}
    for canonical, types, aliases in entries:
        idx[canonical.lower()] = (canonical, types)
        for alias in aliases:
            idx[alias.lower()] = (canonical, types)
    return idx


MALWARE_INDEX       = _index(MALWARE)
THREAT_ACTOR_INDEX  = _index(THREAT_ACTORS)
TOOL_INDEX          = _index(TOOLS)


# Generic words to EXCLUDE from MalwareBazaar Family: field — these are file
# types, not malware families.
GENERIC_FAMILY_BLOCKLIST = {
    "elf", "exe", "dll", "msi", "pdf", "doc", "docx", "xls", "xlsx",
    "ps1", "py", "js", "vbs", "bat", "sh", "html", "lnk", "apk",
    "ipa", "macho", "iso", "img", "zip", "rar", "7z",
    "unknown", "none", "n/a", "",
}
