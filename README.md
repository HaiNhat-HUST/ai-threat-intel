# ai-threat-intel

Pipeline thu thập và xử lý **Cyber Threat Intelligence (CTI)** từ các nguồn công khai, chuẩn hoá theo **STIX 2.1** (chuẩn quốc tế OASIS Open), trích xuất entity (IOC / Vulnerability / Malware / Threat-Actor / Tool / MITRE ATT&CK technique) qua 3 tier, và xuất ra đồ thị threat-intel có cấu trúc — sẵn sàng cho RAG + dashboard.

## Kiến trúc 6 tầng

```
┌─────────────────────────────────────────────────────────────┐
│ Tầng 1 — Collection                              (Hùng)     │
│   Crawl NVD, CISA KEV, GitHub Advisories, AlienVault OTX,  │
│   Abuse.ch (ThreatFox, MalwareBazaar), The Hacker News,    │
│   Threatpost, SANS ISC, Reddit                              │
│   → SQLite table threat_articles                            │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Tầng 2 — Normalization & Cleaning                (Vinh)    │
│   strip HTML/markdown, normalize severity, dedup near-     │
│   duplicate (MinHash + LSH), language detect & filter,     │
│   timestamp → UTC, emit STIX Report SDO + Identity +       │
│   Grouping, TLP:WHITE marking                              │
│   → table stix_objects + stix_relationships                 │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Tầng 3 — Entity Extraction (3 tier)              (Vinh)    │
│   Tier 1: regex/iocextract → Indicator + Vulnerability     │
│   Tier 2: gazetteer + structured → Malware + Threat-Actor  │
│   Tier 3: LLM (provider-agnostic) → Attack-Pattern +       │
│             Relationship + severity inference              │
│   → entities + SROs appended to Reports                    │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Tầng 4 — Enrichment                              (Quân)    │
│   VirusTotal, AbuseIPDB, Shodan, GeoIP, WHOIS              │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Tầng 5 — LLM Summarization & RAG                 (Nhật)    │
│   Daily threat brief, campaign briefs, Q&A interface       │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Tầng 6 — Storage & Interface                     (Vinh)    │
│   PostgreSQL JSONB + vector DB (Qdrant/Chroma),            │
│   dashboard Streamlit/Next.js, TAXII server (optional)     │
└─────────────────────────────────────────────────────────────┘
```

## Quick start

```bash
git clone https://github.com/HaiNhat-HUST/ai-threat-intel.git
cd ai-threat-intel

# Cài deps
pip install -r requirements.txt

# Khởi tạo DB từ baseline (sample của Hùng, 90 article)
cp src/collectors/threat_intel.db.sample src/collectors/threat_intel.db

# (Hoặc tự crawl mới bằng Layer 1 collectors của Hùng)
# python src/collectors/main.py

# Chạy Layer 2: normalization + STIX SDO emission
python src/processing/run.py --reset

# Chạy Layer 3: entity extraction (Tier 1 + 2 + 3 mock LLM)
python src/extraction/run.py

# Tests
pytest tests/                  # 99 tests, ~1.5s
```

## Cấu trúc repo

```
ai-threat-intel/
├── README.md                     ← bạn đang đọc
├── requirements.txt              ← dependencies cho cả 6 tầng
├── docker-compose.yml            ← Postgres + vector DB (Layer 6, sẽ thêm)
├── docs/
│   ├── STIX_mapping_layers_2_3_6.md   ← design doc STIX schema
│   └── Layer_2_3_Report.docx          ← báo cáo chi tiết Layer 2 + 3
├── src/
│   ├── collectors/               ← Layer 1 (Hùng)
│   │   ├── README.md
│   │   ├── nvd_collector.py
│   │   ├── cisa_kev_collector.py
│   │   ├── abusech_collector.py
│   │   ├── otx_collector.py
│   │   ├── reddit_collector.py
│   │   ├── github_collector.py
│   │   ├── rss_collector.py
│   │   ├── models.py             ← ORM threat_articles
│   │   └── threat_intel.db.sample   ← baseline data, copy thành .db
│   ├── processing/               ← Layer 2 (Vinh)
│   │   ├── README.md
│   │   ├── clean.py              ← strip + normalize + langdetect + severity
│   │   ├── dedup.py              ← MinHash + LSH + Union-Find
│   │   ├── schema.py             ← ORM stix_objects + stix_relationships
│   │   ├── report_builder.py     ← STIX SDO factories
│   │   └── run.py                ← CLI end-to-end
│   ├── extraction/               ← Layer 3 (Vinh)
│   │   ├── README.md
│   │   ├── builders.py           ← Indicator/Vulnerability/Malware/... factories
│   │   ├── tier1_regex.py        ← Tier 1: iocextract + defang/refang
│   │   ├── tier2_ner.py          ← Tier 2: structured + gazetteer
│   │   ├── tier3_llm.py          ← Tier 3: provider-agnostic LLM pipeline
│   │   ├── gazetteer.py          ← ~150 malware/actor/tool names
│   │   ├── attack_kb.py          ← 58 MITRE ATT&CK techniques
│   │   ├── llm/                  ← LLMProvider Protocol + Mock + stubs
│   │   │   ├── base.py
│   │   │   ├── mock.py
│   │   │   ├── claude.py         ← stub, cần implement
│   │   │   ├── openai_.py        ← stub
│   │   │   ├── ollama.py         ← stub
│   │   │   ├── factory.py        ← get_provider() đọc env LLM_PROVIDER
│   │   │   └── cache.py          ← file-based prompt cache
│   │   └── run.py                ← CLI: python src/extraction/run.py
│   ├── enrichment/               ← Layer 4 (Quân)
│   ├── llm/                      ← Layer 5 (Nhật)
│   ├── storage/                  ← Layer 6 (Vinh, sẽ thêm)
│   └── dashboard/                ← Layer 6
└── tests/
    ├── processing/               ← 47 tests Layer 2
    └── extraction/               ← 52 tests Layer 3
```

## Standards & Tech stack

- **STIX 2.1** (OASIS Open) — schema chính cho threat intel objects
- **MITRE ATT&CK** — knowledge base cho technique mapping
- **TLP** (Traffic Light Protocol) — sharing markings
- **SQLAlchemy** + SQLite (dev) / PostgreSQL (prod)
- **datasketch** (MinHash + LSH) cho near-duplicate dedup
- **lingua** cho multilingual language detection
- **iocextract** cho IOC regex + defang/refang
- **stix2** (python-stix2, official OASIS lib) cho SDO build + validation
- **pytest** cho unit testing

## Trạng thái hiện tại

| Layer | Owner | Status |
|---|---|---|
| 1 — Collection | Hùng | ✅ Done (17 sources, 90 sample articles) |
| 2 — Normalization | Vinh | ✅ Done (108 stix_objects, 99 tests) |
| 3 — Entity Extraction | Vinh | ✅ Done (3 tiers, 348 entities + 111 relationships) |
| 4 — Enrichment | Quân | ⏳ In progress |
| 5 — LLM Summarization | Nhật | ⏳ In progress |
| 6 — Storage & Interface | Vinh | ⏳ Sau khi 4 + 5 xong |

## Documentation

- **[docs/STIX_mapping_layers_2_3_6.md](docs/STIX_mapping_layers_2_3_6.md)** — design reference cho schema STIX 2.1
- **[docs/Layer_2_3_Report.docx](docs/Layer_2_3_Report.docx)** — báo cáo chi tiết Layer 2 + 3 (kiến trúc, code, kết quả)
- **[src/processing/README.md](src/processing/README.md)** — Layer 2 user guide
- **[src/extraction/README.md](src/extraction/README.md)** — Layer 3 user guide

## Contributors

- **Hùng** — Layer 1 (Collection)
- **Vinh** — Layer 2, 3, 6 (Normalization, Extraction, Storage)
- **Quân** — Layer 4 (Enrichment)
- **Nhật** — Layer 5 (LLM Summarization + RAG)

## License

Academic project — HUST.
