"""
src/extraction/ - Layer 3: Entity Extraction.

Owner: Vinh
Input:  stix_objects WHERE type='report' (output of Layer 2)
Output: indicator, vulnerability SDOs in stix_objects;
        relationship SROs in stix_relationships;
        Report.object_refs updated to include extracted entities.

Pipeline (run by `python src/extraction/run.py`):
    Tier 1 - regex / iocextract (no AI)   <- CURRENT
        CVE, IPv4/IPv6, domain, URL, file hashes (MD5/SHA1/SHA256),
        email, Bitcoin address; defang/refang; structured parsers for
        ThreatFox / MalwareBazaar.

    Tier 2 - NER (spaCy / SecureBERT)       <- next
        Malware family, threat-actor, tool names.

    Tier 3 - LLM (Claude / GPT-4 / Llama)  <- last
        MITRE ATT&CK technique mapping, relationship inference,
        severity for remaining None rows.
"""
