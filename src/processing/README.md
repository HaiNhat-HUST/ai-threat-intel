# Layer 2 — Normalization & Cleaning

Owner: **Vinh**
Input:  `src/collectors/threat_intel.db` (table `threat_articles`, Layer 1 output)
Output: bảng `stix_objects` + `stix_relationships` trong **cùng DB**

## Setup lần đầu

`*.db` được gitignored — bạn phải khởi tạo từ baseline trước khi chạy lần đầu:

```bash
cp src/collectors/threat_intel.db.sample src/collectors/threat_intel.db
```

(`.db.sample` chứa 90 article của Hùng làm sample; nếu muốn data thật mới hãy chạy `python src/collectors/main.py` để crawl từ các nguồn.)

## Pipeline tổng quan

```
threat_articles (90 rows từ 17 nguồn)
   │
   ▼
clean.py            ─ strip HTML/markdown, normalize severity (CRITICAL/Critical → critical),
                      timestamp → UTC, detect language (en/vi/zh/...),
                      infer severity từ KEV/CVSS khi nguồn không cung cấp
   │
   ▼
dedup.py            ─ MinHash + LSH + Union-Find tìm near-duplicate
                      (threshold 0.85 mặc định)
   │
   ▼
report_builder.py   ─ với mỗi article: build STIX Report SDO + Identity SDO,
                      gắn TLP:WHITE marking, deterministic UUIDv5 id
                      với cluster size > 1: build thêm Grouping SDO
                      (context="same-incident") để giữ bằng chứng đa nguồn
   │
   ▼
schema.py           ─ persist tất cả vào stix_objects + stix_relationships
                      qua session.merge() (idempotent UPSERT)
```

## Cách chạy

```bash
# từ project root, sau khi pip install -r requirements.txt
python src/processing/run.py

# Tuỳ chọn:
python src/processing/run.py --threshold 0.8           # near-dup chặt hơn
python src/processing/run.py --limit 20                # debug nhanh
python src/processing/run.py --reset                   # xoá stix_objects cũ trước
python src/processing/run.py --allowed-langs en,vi,zh  # ngôn ngữ giữ cho RAG
```

## Bảng `stix_objects` (output chính)

| Cột | Kiểu | Ghi chú |
|---|---|---|
| `id` | TEXT PK | STIX id, vd `report--71850b62-...` (UUIDv5 deterministic) |
| `type` | TEXT (indexed) | `report` / `identity` / `grouping` / `marking-definition` |
| `name` | TEXT | denormalized cho search |
| `source` | TEXT (indexed) | nguồn (CISA KEV, NVD, …) |
| `severity` | TEXT (indexed) | critical / high / medium / low / info / NULL |
| `lang` | TEXT | ISO 639-1 (en / vi / zh / …) |
| `published` | DATETIME (indexed) | UTC |
| `created`, `modified` | DATETIME | STIX timestamps |
| `raw_article_id` | TEXT (indexed) | trace ngược về `threat_articles.id` |
| `doc` | TEXT (JSONB-equiv) | full STIX JSON object |

## Custom properties (`x_` prefix) trên Report

| Property | Mục đích |
|---|---|
| `x_severity` | severity đã chuẩn hoá (vì STIX 2.1 không có field này native) |
| `x_raw_article_id` | id trong `threat_articles` để truy ngược |
| `x_content_hash` | SHA-256 của Hùng — Layer 3 dùng để exact-dedup nhanh |
| `x_lang_excluded` | `True` khi `lang` không trong `--allowed-langs` (Layer 6 có thể skip embedding) |

## Hợp đồng với Layer 3 (Entity Extraction)

Layer 3 chỉ cần:
1. Đọc tất cả row `WHERE type='report'` từ `stix_objects`
2. Trên field `description` của mỗi Report, chạy regex / NER / LLM để rút entity
3. Tạo Indicator / Vulnerability / Malware / Threat-Actor / Attack-Pattern SDOs (cũng dùng `_det_id()` từ `report_builder.py`)
4. Tạo Relationship SROs vào `stix_relationships`
5. Update `object_refs` của Report để bao gồm các entity id mới

## Test

```bash
pip install pytest
pytest tests/                  # 47 tests, ~1.5s
pytest tests/ -v               # verbose
```

Test coverage:
- `tests/processing/test_clean.py` — strip HTML/MD, severity normalize, severity inference (KEV + CVSS regex), timestamp UTC, language detection (English / **Vietnamese** / **Chinese** / empty)
- `tests/processing/test_dedup.py` — MinHash clustering, singleton vs multi-member, canonical ordering
- `tests/processing/test_report_builder.py` — deterministic id idempotency, identity cache, STIX 2.1 re-parse validation, TLP marking presence, custom properties

## Modules

- `__init__.py` — module overview
- `clean.py` — pure functions cho clean/normalize/infer/lang detect
- `dedup.py` — MinHash + LSH + Union-Find clustering
- `report_builder.py` — Identity, Report, Grouping, TLP factory functions
- `schema.py` — SQLAlchemy ORM cho `stix_objects` + `stix_relationships`
- `run.py` — CLI end-to-end pipeline
