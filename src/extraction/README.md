# Layer 3 — Entity Extraction (3 tier)

Owner: **Vinh**
Input:  bảng `stix_objects WHERE type='report'` (do Layer 2 sinh ra)
Output: thêm các SDO (Indicator, Vulnerability, Malware, Threat-Actor, Tool, Attack-Pattern) và SRO (Relationship) vào cùng DB; `object_refs` của mỗi Report được append.

## Triết lý 3-tier

| Tier | Phương pháp | Output | Chi phí |
|---|---|---|---|
| **1** | Regex + iocextract + structured parser | Indicator, Vulnerability | Rất rẻ (CPU only) |
| **2** | Structured (ThreatFox/MalwareBazaar) + Gazetteer match | Malware, Threat-Actor, Tool | Rẻ (CPU only) |
| **3** | LLM (provider-agnostic) | Attack-Pattern, Relationship, severity infer | Tốn token (real LLM) |

Mỗi tier consume output của tier trước. Tất cả dùng cùng `_det_id` (deterministic UUIDv5) → cùng IOC value qua nhiều report → cùng SDO id → đồ thị tự nhiên hình thành.

## Pipeline overview

```
stix_objects (type='report')   ← Layer 2 output
   │
   ▼
extract_iocs(description)              [Tier 1 — tier1_regex.py]
   ├─ CVE pattern → build_vulnerability
   ├─ IPv4/IPv6/domain/URL → build_indicator_*
   ├─ MD5/SHA1/SHA256/SHA512 → build_indicator_file_hash
   ├─ email, Bitcoin → build_indicator_*
   ├─ defang/refang (1.2.3[.]4 → 1.2.3.4, hxxp://... → http://...)
   └─ ThreatFox/MalwareBazaar structured-only fast path
   │
   ▼
extract_entities(description)          [Tier 2 — tier2_ner.py]
   ├─ Structured: parse "Malware:", "Family:" + platform prefix strip
   ├─ Gazetteer match: ~150 known malware/actor/tool names
   ├─ Skip generic scan cho structured source (tránh "Reporter: anonymous"
   │   match Anonymous hacktivist)
   └─ emit Malware/Threat-Actor/Tool SDO
   │   plus indicator-INDICATES-malware Relationship
   │
   ▼
enrich_report(...)                     [Tier 3 — tier3_llm.py]
   ├─ provider.classify_attack_pattern → Attack-Pattern SDO
   ├─ provider.infer_relationships → relationship SROs
   │   (actor-uses-malware, malware-uses-AP, AP-targets-vuln, ...)
   └─ provider.infer_severity → bổ sung severity cho Report None
```

## Cách chạy

```bash
# Cần Layer 2 đã chạy trước
python src/processing/run.py --reset

# Layer 3 — mọi tier với MockProvider (default)
python src/extraction/run.py

# Tuỳ chọn
python src/extraction/run.py --tier 1            # chỉ Tier 1
python src/extraction/run.py --tier 1,2          # bỏ Tier 3
python src/extraction/run.py --tier 1,2,3        # full pipeline
python src/extraction/run.py --reset             # xoá L3 SDO + SRO cũ
python src/extraction/run.py --limit 20          # debug

# Khi đội chốt LLM
export LLM_PROVIDER=claude
export ANTHROPIC_API_KEY=sk-...
python src/extraction/run.py --tier 3
```

## Provider-agnostic LLM (Tier 3)

Mọi LLM call đi qua Protocol `LLMProvider` (3 method: `classify_attack_pattern`, `infer_relationships`, `infer_severity`). Default là `MockProvider` chạy rule-based deterministic. Khi đội chốt model, viết 1 adapter class trong `llm/claude.py` / `llm/openai_.py` / `llm/ollama.py` và đổi env `LLM_PROVIDER` — code Tier 3 (`tier3_llm.py`, `run.py`, `builders.py`) **không cần đổi gì**.

`MockProvider` không phải toy:
- `classify_attack_pattern` — gazetteer match 58 ATT&CK technique keywords trong `attack_kb.py`
- `infer_relationships` — rule-based theo type pairs (actor+malware → uses, AP+vuln → targets, ...)
- `infer_severity` — regex keyword (`pre-auth RCE` → critical, `high severity` → high, ...)

Coverage ~60% case. Real LLM giải quyết edge case + ngữ cảnh phức tạp.

### Implement provider thật

Mỗi file stub (`llm/claude.py`, `llm/openai_.py`, `llm/ollama.py`) đã có class skeleton + `NotImplementedError` + comment hướng dẫn. Workflow:

1. `pip install anthropic` (hoặc `openai` / `httpx`)
2. Xoá `NotImplementedError`, implement 3 method bằng SDK + prompt template
3. Dùng `llm/cache.py` (file-based hash cache) để tiết kiệm token khi re-run
4. `export LLM_PROVIDER=claude` + API key

## Schema xuống `stix_objects`

| Cột | Layer 3 set khi nào |
|---|---|
| `id` | Deterministic UUIDv5 keyed observable/CVE/technique value |
| `type` | indicator / vulnerability / malware / threat-actor / tool / attack-pattern |
| `name` | Denormalized cho dashboard search |
| `source` | NULL với entity (chia sẻ cross-report) |
| `severity`, `lang`, `published`, `raw_article_id` | NULL với entity |
| `doc` | Full STIX 2.1 JSON |

## Schema xuống `stix_relationships`

```
id                  STRING  PK   # relationship--<uuidv5>
source_ref          STRING       # SDO id phía nguồn
target_ref          STRING       # SDO id phía đích
relationship_type   STRING       # 'indicates' / 'uses' / 'targets' / ...
created, modified, doc
INDEX (source_ref, target_ref)   # cho graph query
```

## Modules

- **`builders.py`** — factory cho tất cả SDO + Relationship. Deterministic UUIDv5 keyed theo VALUE.
- **`tier1_regex.py`** — `extract_iocs(text, source)` dùng iocextract + custom CVE/BTC regex + ThreatFox/MalwareBazaar structured parser. Defang/refang trước khi match.
- **`tier2_ner.py`** — `extract_entities(text, source)` dùng gazetteer + structured-source bypass.
- **`gazetteer.py`** — 56 malware + 32 threat-actor + 23 tool entries với aliases (~150 lookup keys). Plus `GENERIC_FAMILY_BLOCKLIST` để filter file type khỏi MalwareBazaar `Family:` field.
- **`attack_kb.py`** — 58 MITRE ATT&CK Enterprise technique với keyword index cho MockProvider match.
- **`tier3_llm.py`** — `enrich_report(description, t1_entities, t2_entities, provider)` orchestrate 3 lời gọi provider.
- **`llm/`** — package với Protocol, MockProvider, factory, cache, và 3 stub provider.
- **`run.py`** — CLI tích hợp tất cả 3 tier với in-memory dedup + idempotent merge.

## Custom properties trên Indicator/Vulnerability

Tất cả SDO Layer 3 emit gắn `object_marking_refs=[TLP_WHITE.id]` và `allow_custom=True`. Hiện chưa dùng `x_` props ở Layer 3 — nếu cần (vd `x_confidence` cho Tier 3 LLM output), thêm vào `_make_indicator` trong `builders.py`.

## Idempotency

Cùng input → cùng output, cross-run:

```bash
# Lần 1
python src/extraction/run.py
# DONE. 337 entities, 111 relationships persisted.

# Lần 2 — không thay đổi gì
python src/extraction/run.py
# DONE. 337 entities, 111 relationships persisted.
# (session.merge() phát hiện id đã tồn tại → UPDATE, không INSERT thêm)
```

## Tests

```bash
pytest tests/extraction/                 # 52 tests
pytest tests/extraction/test_tier1_regex.py -v
```

Test fixtures gồm sample ThreatFox/MalwareBazaar/Hacker News, defang/refang test cases, và idempotency check cho deterministic IDs.

## Roadmap

- [ ] Thêm spaCy/SecureBERT NER bên cạnh gazetteer cho prose (Tier 2 enhancement).
- [ ] Implement Claude/OpenAI/Ollama adapter thật (15-50 dòng SDK glue per provider).
- [ ] Mở rộng gazetteer khi corpus có tên mới (Clearfake, Kimwolf, Strelastealer hiện emit raw).
- [ ] Custom properties `x_confidence`, `x_first_seen`, `x_last_seen` cho Indicator (cần khi Layer 4 enrichment chạy lại).
