# STIX 2.1 Mapping for `ai-threat-intel` — Layers 2, 3 & 6

**Owner:** Vinh · **Scope:** Normalization (L2), Entity Extraction (L3), Storage & Interface (L6)
**Input:** `threat_intel.db` (Layer 1 output) — 90 rows in `threat_articles`, 17 sources
**Standard:** [STIX 2.1 / OASIS CTI](https://oasis-open.github.io/cti-documentation/) via the official `stix2` Python library

> Every JSON object in this document was built and validated with `python-stix2`, so it is guaranteed spec-correct. The build script lives at `stix_examples.json`.

---

## 1. Why STIX is the right backbone for *your* three layers

Your three layers are the bridge between raw scraped text (Layer 1) and the LLM/RAG steps (Layers 4–5). The hard question for each of them is the same: **"what schema do these entities live in?"** STIX answers it once, for all three:

- **Layer 2** needs a *common schema* to normalize 17 different source formats into. STIX gives you the common properties (`id`, `created`, `modified`, `created_by_ref`, `external_references`, `lang`, `confidence`) for free.
- **Layer 3** extracts entities (CVEs, IPs, hashes, malware, actors, ATT&CK techniques). STIX has a purpose-built object type for *each* of these, plus `relationship` objects to connect them.
- **Layer 6** needs to store and search them. STIX objects are just JSON, so they drop into Postgres `JSONB` and a vector DB cleanly, and you can optionally expose them over **TAXII** for standards-compliant exchange (the second half of "STIX/TAXII").

Net effect: instead of inventing a schema and defending it to your graders, you adopt the one Mandiant, MITRE, CISA, and Recorded Future actually use. That single decision is what makes Layers 2/3/6 hang together.

---

## 2. The STIX object zoo (only the parts you need)

STIX has three kinds of objects. You will use a small, well-chosen subset.

**SDOs — STIX Domain Objects (the "nouns")**

| Object | You create it from… | Layer |
|---|---|---|
| `vulnerability` | CVE / NVD / CISA KEV / GitHub Advisory rows | L3 |
| `indicator` | Any extracted IOC (IP, domain, URL, file hash) — wraps a *pattern* | L3 |
| `malware` | Malware family names (e.g. `win.vshell`, ELF families) | L3 |
| `attack-pattern` | MITRE ATT&CK technique IDs (e.g. `T1190`, `T1195.002`) | L3 (LLM) |
| `threat-actor` / `intrusion-set` | Named actors / groups (e.g. `TeamPCP`) | L3 |
| `tool` | Dual-use tools mentioned (Cobalt Strike, mimikatz…) | L3 |
| `identity` | The *source* that produced the data (CISA, abuse.ch…) | L2 |
| `report` | **One per article** — the narrative + links to everything in it | L2/L3 |
| `course-of-action` | "Required Action" / remediation text (e.g. KEV patch guidance) | L3 |

**SCOs — STIX Cyber-observable Objects (the raw facts inside a pattern)**
`ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `file` (with `hashes.MD5` / `hashes.'SHA-1'` / `hashes.'SHA-256'`), `email-addr`, `autonomous-system`.

**SROs — STIX Relationship Objects (the "verbs")**
`relationship` (typed edges like `indicates`, `uses`, `targets`, `attributed-to`) and `sighting`.

**Container:** `bundle` — a JSON wrapper holding a set of objects for storage or transfer.

---

## 3. Source → STIX mapping (all 17 of your sources)

Your `threat_articles.source` column tells Layer 3 which extractor + object types to apply:

| Source(s) in your DB | Primary STIX output | Notes |
|---|---|---|
| **CISA KEV** | `vulnerability` + `course-of-action` + `report` | flag `actively-exploited`; parse "Required Action" → course-of-action |
| **NVD**, **GitHub Advisories** | `vulnerability` + `report` | CVE id → `external_references`; CVSS → custom prop (see §6) |
| **Abuse.ch ThreatFox** | `indicator` + `malware` + `relationship(indicates)` | `ip:port`, `domain`, `url` IOC types map to SCO patterns |
| **Abuse.ch MalwareBazaar** | `indicator(file hashes)` + `malware` | SHA256/MD5 → `file:hashes` pattern |
| **AlienVault OTX** | `indicator` (+ `malware`/`threat-actor` from pulse) | usually multi-IOC; one indicator per observable |
| **The Hacker News, Threatpost, SANS ISC** | `report` + extracted `vulnerability`/`malware`/`threat-actor`/`attack-pattern` | free text → run full L3 pipeline (regex + NER + LLM) |
| **Reddit (r/netsec, r/malware, …)** | `report` + low-confidence extractions | set low `confidence`; community-sourced |

A clean rule for Layer 2/3: **every row becomes exactly one `report`**, and the report's `object_refs` list points at every entity Layer 3 pulled out of it. The report is your unit of provenance and your RAG retrieval unit.

---

## 4. Four worked examples from your actual rows

### 4A. `vulnerability` + `report` — CISA KEV row (id=1)

Raw: `KEV: CVE-2026-42897 — Microsoft Exchange Server Cross-Site Scripting Vulnerability`

```json
{
  "type": "vulnerability",
  "spec_version": "2.1",
  "id": "vulnerability--42dce028-2d9f-440e-9870-d14c8d228ffe",
  "created_by_ref": "identity--<CISA>",
  "name": "CVE-2026-42897 — Microsoft Exchange Server Cross-Site Scripting Vulnerability",
  "description": "Microsoft Exchange Server contains a cross-site scripting vulnerability in Outlook Web Access; arbitrary JavaScript can be executed in the browser context.",
  "labels": ["cisa-kev", "actively-exploited"],
  "external_references": [
    { "source_name": "cve", "external_id": "CVE-2026-42897" },
    { "source_name": "nvd", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-42897" }
  ]
}
```

The CVE id is **never** a free-text field — it always goes in `external_references` with `source_name: "cve"`. The article itself becomes a `report` whose `object_refs` includes this vulnerability and a `course-of-action` built from the "Required Action" text.

### 4B. `indicator` + `malware` — ThreatFox row (id=71)

Raw: `IOC 60.204.249.248:8084 · Type ip:port · Threat botnet_cc · Malware win.vshell · Confidence 100%`

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--ae73a645-...",
  "name": "ThreatFox C2: 60.204.249.248",
  "description": "botnet_cc infrastructure for win.vshell (confidence 100%)",
  "indicator_types": ["malicious-activity"],
  "pattern": "[ipv4-addr:value = '60.204.249.248']",
  "pattern_type": "stix",
  "valid_from": "2026-05-20T09:28:47Z",
  "external_references": [{ "source_name": "threatfox", "url": "https://threatfox.abuse.ch/ioc/1816571/" }]
}
```

Then link it to the malware family with an SRO:

```json
{ "type": "relationship", "relationship_type": "indicates",
  "source_ref": "indicator--ae73a645-...", "target_ref": "malware--<win.vshell>" }
```

The ThreatFox `Confidence: 100%` maps to the STIX `confidence` property (0–100 integer). The `:8084` port can be captured with a richer `network-traffic` pattern if you want — start simple with the IP.

### 4C. `indicator` with file hashes — MalwareBazaar row (id=61)

Raw: `SHA256 0b26297b… · MD5 b60dd51e… · Family elf`

```json
{
  "type": "indicator",
  "pattern": "[file:hashes.'SHA-256' = '0b26297bcc18752aa239926fdd62c823ec5db618b409e6467c3c42fb2d1430be' OR file:hashes.'MD5' = 'b60dd51e91841ea346b7a66aa97e9265']",
  "pattern_type": "stix",
  "indicator_types": ["malicious-activity"],
  "valid_from": "2026-05-20T09:31:37Z"
}
```

Note the exact STIX hash key spelling: `SHA-256`, `SHA-1`, `MD5` (with the hyphens and quotes inside the pattern).

### 4D. Narrative article → `report` + `threat-actor` + `attack-pattern` — The Hacker News row (id=21)

Raw: *"Grafana GitHub Breach … originated from the TanStack npm supply chain attack orchestrated by TeamPCP …"*

This is where **LLM extraction (your Layer 3 hard path)** earns its keep — pulling `TeamPCP` as a `threat-actor` and inferring the ATT&CK technique:

```json
{ "type": "threat-actor", "name": "TeamPCP", "threat_actor_types": ["crime-syndicate"] }
{ "type": "attack-pattern", "name": "Compromise Software Supply Chain",
  "external_references": [{ "source_name": "mitre-attack", "external_id": "T1195.002",
    "url": "https://attack.mitre.org/techniques/T1195/002/" }] }
{ "type": "relationship", "relationship_type": "uses",
  "source_ref": "threat-actor--<TeamPCP>", "target_ref": "attack-pattern--<T1195.002>" }
```

The `report` then ties the whole story together:

```json
{ "type": "report", "report_types": ["threat-report"],
  "name": "Grafana GitHub Breach Exposes Source Code via TanStack npm Attack",
  "published": "2026-05-20T05:12:06Z",
  "object_refs": ["threat-actor--<TeamPCP>", "attack-pattern--<T1195.002>", "relationship--..."] }
```

---

## 5. How STIX drives each of your layers

### Layer 2 — Normalization & Cleaning → "fill the STIX common fields"
Reframe Layer 2 as "produce a clean `report` SDO per article." Concretely:

- **HTML/markdown strip** → clean text into `report.description` (your DB has markdown like `### Summary` and fenced code in NVD rows, plus 1 HTML row — use `BeautifulSoup` + a markdown stripper).
- **Timestamp → UTC** → `published` / `valid_from` in STIX timestamp format (`...Z`). Your `published_at` is already datetime; just enforce the `Z` suffix.
- **Language** → set the STIX `lang` property (e.g. `"en"`); your multilingual handling (detect + translate/filter) decides what goes in `lang` and whether you translate `description`. Use `lingua` or `fasttext` for detection.
- **Near-duplicate dedup** → Layer 1's `content_hash` already removes *exact* dupes (all 90 rows are distinct hashes). Your job is *near*-dupes (same incident reported by THN + Threatpost + Reddit). Use **MinHash + LSH** (`datasketch`); when you find a cluster, emit one `report` and use a `relationship(type="derived-from")` or a `grouping` object to keep the rest as evidence.
- **Source normalization** → each distinct `source` becomes an `identity` object referenced via `created_by_ref`. Also normalize the messy `severity` column here (your data mixes `CRITICAL`/`Critical` and has 32 NULLs — lowercase + map to a fixed set, infer from CVSS/KEV when missing).

### Layer 3 — Entity Extraction → "emit the right SDO per entity"
Your three-tier extraction maps directly onto object types:

| Tier | Tool | Produces |
|---|---|---|
| Regex / rule-based | `iocextract` (+ defang/refang) | `indicator` patterns over `ipv4-addr`, `domain-name`, `url`, `file:hashes`, `email-addr`; `vulnerability` from CVE regex |
| NER | spaCy / SecureBERT / CyBERT | `malware`, `threat-actor`, `tool` names |
| LLM (hard cases only) | Claude / local Llama | `attack-pattern` (ATT&CK TTP IDs), `relationship` inference, severity/`confidence` |

Critical detail from your task sheet: **defang/refang before patterning**. `iocextract.refang_ipv4("60.204.249[.]248")` → `60.204.249.248` so the STIX pattern is valid. Build a thin `to_indicator(observable, type)` helper so every IOC becomes a well-formed pattern.

### Layer 6 — Storage & Interface → "STIX in, search out"
- **PostgreSQL (structured):** one table `stix_objects(id PK, type, created, modified, source, severity, valid_from, doc JSONB)` with a **GIN index on `doc`**. SROs (`relationship`) can live in the same table or a dedicated `stix_relationships` table for fast graph queries. This makes the dashboard's filter-by-date/severity/actor trivial (`WHERE type='report' AND severity='critical'`).
- **Vector DB (semantic search / RAG):** embed each `report.description` (and indicator descriptions) with `sentence-transformers`; store the vector with metadata `{stix_id, type, source, published, severity}`. At query time, retrieve → return `stix_id` → resolve the full object from Postgres. This is exactly what Layer 5's "RAG with citation" needs — the `stix_id` *is* the citation.
- **Dashboard:** Streamlit is the fastest path to a demo (all-Python, integrates with your pipeline directly); Next.js if the team wants a more production-like UI. Pages: list/filter reports, IOC search, and a detail page that renders a `report` plus its `object_refs` as a small entity graph.
- **TAXII (optional stretch, high marks):** wrap your bundles in a TAXII 2.1 server (`medallion` reference server) so other tools can pull your feed. This is the part most student projects skip — implementing even a read-only TAXII collection demonstrates you understood the *exchange* half of STIX/TAXII.

---

## 6. Gotchas worth knowing now

- **CVSS is not a native field** on the `vulnerability` SDO in STIX 2.1. Store CVSS score/vector either as a custom property (`x_cvss_score`) or — cleaner — as a column in your Postgres layer and keep the SDO standards-pure. Same for your `severity` column: there is no standard `severity` on most SDOs, so keep it as a relational column and/or `x_severity` custom property; use the native `confidence` (0–100) for source trust.
- **Custom properties must be prefixed** `x_` (e.g. `x_severity`, `x_cvss_score`) or `python-stix2` rejects them in strict mode.
- **Pattern hash keys are case- and quote-sensitive:** `file:hashes.'SHA-256'`, `file:hashes.'SHA-1'`, `file:hashes.MD5`.
- **TLP markings:** attach `object_marking_refs` pointing at a TLP marking-definition (e.g. `TLP:CLEAR` for public feeds) so downstream consumers know the sharing level.
- **IDs are deterministic if you want them to be:** by default `python-stix2` random-UUIDs each object, which breaks dedup across runs. For idempotent re-ingestion, generate **deterministic UUIDv5** ids from a namespace + the canonical IOC/CVE value so the same observable always yields the same `id`.

---

## 7. Suggested libraries (your `requirements.txt` starting point)

```
stix2                 # build/validate STIX 2.1 objects (core)
iocextract            # regex IOC extraction + defang/refang (L3 tier 1)
beautifulsoup4        # HTML strip (L2)
markdown-it-py        # markdown strip (L2)
datasketch            # MinHash/LSH near-dup dedup (L2)
lingua-language-detector  # language detection (L2 multilingual)
spacy                 # NER for malware/actor/tool (L3 tier 2)
sentence-transformers # embeddings for RAG (L6)
chromadb              # vector DB — simplest; or qdrant-client (L6)
sqlalchemy + psycopg  # PostgreSQL access (L6)
medallion / taxii2-client  # optional TAXII server/client
```

---

## 8. Recommended build order

1. Stand up the `identity` objects (one per source) + the `report`-per-row skeleton (L2).
2. Add cleaning: HTML/markdown strip, UTC timestamps, `lang`, severity normalization (L2).
3. Add near-dup dedup with MinHash/LSH (L2).
4. Wire regex IOC extraction → `indicator` patterns + defang/refang (L3 tier 1).
5. Add NER → `malware`/`threat-actor`/`tool` (L3 tier 2).
6. Add LLM ATT&CK tagging + relationship inference (L3 tier 3).
7. Persist bundles to Postgres `JSONB` + embed into the vector DB (L6).
8. Build the Streamlit dashboard; (stretch) expose a TAXII collection (L6).

Each step produces valid STIX you can validate with `python-stix2` and eyeball in VS Code's JSON viewer — so you always have a working, demoable artifact.
