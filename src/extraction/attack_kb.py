"""
attack_kb.py - MITRE ATT&CK technique catalog cho Tier 3 LLM.

50+ kỹ thuật phổ biến nhất từ ATT&CK Enterprise. Mỗi entry:
    technique_id  - T-code chuẩn (T1190, T1566.001, ...)
    name          - canonical name của technique
    tactic        - kill chain phase (initial-access, execution, ...)
    keywords      - các cụm từ để mock match trong description
    url           - link tới trang technique trên attack.mitre.org

Mock provider dùng keywords cho exact-match (case-insensitive, word-boundary).
Real LLM dùng catalog này như danh sách candidate + context (id + name + keywords)
trong prompt.
"""
from __future__ import annotations

# (technique_id, name, tactic, keywords)
TECHNIQUES: list[tuple[str, str, str, list[str]]] = [
    # ─── Initial Access ─────────────────────────────────
    ("T1190", "Exploit Public-Facing Application", "initial-access",
     ["remote code execution", "rce", "0day", "zero-day", "web vulnerability",
      "publicly exposed", "internet-facing", "exploit public", "web shell"]),
    ("T1133", "External Remote Services", "initial-access",
     ["rdp", "remote desktop protocol", "vpn compromise", "exposed rdp"]),
    ("T1566", "Phishing", "initial-access",
     ["phishing campaign", "phishing email"]),
    ("T1566.001", "Spearphishing Attachment", "initial-access",
     ["malicious attachment", "weaponized document", "spearphishing attachment",
      "macro-enabled document"]),
    ("T1566.002", "Spearphishing Link", "initial-access",
     ["spearphishing link", "phishing link", "credential phishing"]),
    ("T1195", "Supply Chain Compromise", "initial-access",
     ["supply chain compromise", "supply chain attack"]),
    ("T1195.001", "Compromise Software Dependencies and Development Tools",
     "initial-access",
     ["dependency confusion", "malicious package", "typosquatting"]),
    ("T1195.002", "Compromise Software Supply Chain", "initial-access",
     ["tanstack", "npm supply chain", "pypi malicious package",
      "compromised package", "software supply chain"]),
    ("T1078", "Valid Accounts", "initial-access",
     ["stolen credentials", "credential abuse", "valid account",
      "compromised account", "leaked credentials"]),
    ("T1199", "Trusted Relationship", "initial-access",
     ["trusted third party", "msp compromise"]),

    # ─── Execution ──────────────────────────────────────
    ("T1059", "Command and Scripting Interpreter", "execution",
     ["command line interpreter", "shell command"]),
    ("T1059.001", "PowerShell", "execution",
     ["powershell", "powershell script"]),
    ("T1059.003", "Windows Command Shell", "execution",
     ["cmd.exe", "windows command shell"]),
    ("T1204", "User Execution", "execution",
     ["user execution", "user clicked"]),
    ("T1204.002", "Malicious File", "execution",
     ["malicious file execution", "user opened"]),
    ("T1053", "Scheduled Task/Job", "execution",
     ["scheduled task", "cron job", "task scheduler"]),

    # ─── Persistence ────────────────────────────────────
    ("T1547", "Boot or Logon Autostart Execution", "persistence",
     ["autostart", "run key", "startup folder"]),
    ("T1543", "Create or Modify System Process", "persistence",
     ["windows service", "system service", "service persistence"]),
    ("T1136", "Create Account", "persistence",
     ["new account created", "rogue account"]),
    ("T1098", "Account Manipulation", "persistence",
     ["account manipulation", "added permissions"]),

    # ─── Privilege Escalation ───────────────────────────
    ("T1068", "Exploitation for Privilege Escalation", "privilege-escalation",
     ["privilege escalation", "elevation of privilege", "eop"]),
    ("T1134", "Access Token Manipulation", "privilege-escalation",
     ["token impersonation", "access token"]),

    # ─── Defense Evasion ────────────────────────────────
    ("T1027", "Obfuscated Files or Information", "defense-evasion",
     ["obfuscated", "obfuscation", "packed binary", "encoded payload"]),
    ("T1140", "Deobfuscate/Decode Files or Information", "defense-evasion",
     ["deobfuscate", "decode payload"]),
    ("T1562", "Impair Defenses", "defense-evasion",
     ["disable antivirus", "kill edr", "impair defenses"]),
    ("T1562.001", "Disable or Modify Tools", "defense-evasion",
     ["disable security tool", "tamper with edr"]),
    ("T1070", "Indicator Removal", "defense-evasion",
     ["clear logs", "delete logs", "event log cleared"]),
    ("T1218", "System Binary Proxy Execution", "defense-evasion",
     ["lolbin", "rundll32", "mshta", "regsvr32"]),
    ("T1497", "Virtualization/Sandbox Evasion", "defense-evasion",
     ["sandbox evasion", "vm detection"]),

    # ─── Credential Access ──────────────────────────────
    ("T1003", "OS Credential Dumping", "credential-access",
     ["credential dumping", "dump credentials"]),
    ("T1003.001", "LSASS Memory", "credential-access",
     ["lsass dump", "lsass memory", "mimikatz lsass"]),
    ("T1110", "Brute Force", "credential-access",
     ["brute force", "password spraying", "credential stuffing"]),
    ("T1555", "Credentials from Password Stores", "credential-access",
     ["browser password", "stored credentials"]),
    ("T1056", "Input Capture", "credential-access",
     ["keylogger", "keylogging", "input capture"]),

    # ─── Discovery ──────────────────────────────────────
    ("T1018", "Remote System Discovery", "discovery",
     ["network discovery", "host enumeration"]),
    ("T1083", "File and Directory Discovery", "discovery",
     ["file enumeration", "directory listing"]),
    ("T1087", "Account Discovery", "discovery",
     ["account enumeration", "user enumeration"]),
    ("T1049", "System Network Connections Discovery", "discovery",
     ["netstat", "network connections enumeration"]),
    ("T1057", "Process Discovery", "discovery",
     ["process enumeration"]),

    # ─── Lateral Movement ───────────────────────────────
    ("T1021", "Remote Services", "lateral-movement",
     ["lateral movement", "remote service"]),
    ("T1021.001", "Remote Desktop Protocol", "lateral-movement",
     ["rdp lateral", "rdp pivot"]),
    ("T1021.002", "SMB/Windows Admin Shares", "lateral-movement",
     ["smb share", "admin$", "psexec"]),
    ("T1021.004", "SSH", "lateral-movement",
     ["ssh pivot", "ssh lateral"]),

    # ─── Collection ─────────────────────────────────────
    ("T1119", "Automated Collection", "collection",
     ["automated collection"]),
    ("T1005", "Data from Local System", "collection",
     ["data collection from local"]),

    # ─── Command and Control ────────────────────────────
    ("T1071", "Application Layer Protocol", "command-and-control",
     ["c2 channel", "c&c channel"]),
    ("T1071.001", "Web Protocols", "command-and-control",
     ["https c2", "http beacon", "web c2"]),
    ("T1090", "Proxy", "command-and-control",
     ["proxy chain", "c2 proxy"]),
    ("T1572", "Protocol Tunneling", "command-and-control",
     ["dns tunneling", "icmp tunneling"]),
    ("T1573", "Encrypted Channel", "command-and-control",
     ["encrypted c2"]),

    # ─── Exfiltration ───────────────────────────────────
    ("T1041", "Exfiltration Over C2 Channel", "exfiltration",
     ["data exfiltration over c2", "exfiltrate via c2"]),
    ("T1567", "Exfiltration Over Web Service", "exfiltration",
     ["exfiltrate to cloud", "data uploaded to"]),
    ("T1048", "Exfiltration Over Alternative Protocol", "exfiltration",
     ["dns exfiltration", "ftp exfiltration"]),

    # ─── Impact ─────────────────────────────────────────
    ("T1486", "Data Encrypted for Impact", "impact",
     ["ransomware", "data encryption", "encrypted files", "ransom note"]),
    ("T1485", "Data Destruction", "impact",
     ["wiper", "data destruction", "destructive malware"]),
    ("T1491", "Defacement", "impact",
     ["defaced website", "site defacement"]),
    ("T1499", "Endpoint Denial of Service", "impact",
     ["endpoint dos", "crash service"]),
    ("T1498", "Network Denial of Service", "impact",
     ["ddos attack", "network dos", "denial of service"]),
]


def attack_url(technique_id: str) -> str:
    """Build mitre.org URL từ T-code (vd T1566.001 → .../techniques/T1566/001/)."""
    parts = technique_id.split(".")
    if len(parts) == 1:
        return f"https://attack.mitre.org/techniques/{parts[0]}/"
    return f"https://attack.mitre.org/techniques/{parts[0]}/{parts[1]}/"


# Lookup index: keyword -> list of (technique_id, name, tactic)
def _build_keyword_index() -> dict[str, list[tuple[str, str, str]]]:
    idx: dict[str, list[tuple[str, str, str]]] = {}
    for tid, name, tactic, keywords in TECHNIQUES:
        entry = (tid, name, tactic)
        for kw in keywords:
            idx.setdefault(kw.lower(), []).append(entry)
    return idx


KEYWORD_INDEX = _build_keyword_index()


# Lookup by T-code (for builders / tests)
TECHNIQUE_BY_ID: dict[str, tuple[str, str, list[str]]] = {
    tid: (name, tactic, keywords) for tid, name, tactic, keywords in TECHNIQUES
}
