"""
src/processing/ — Layer 2: Normalization & Cleaning

Owner: Vinh
Input:  src/collectors/threat_intel.db  (table: threat_articles)
Output: bảng stix_objects + stix_relationships trong cùng DB
        (xem schema.py)

Pipeline (chạy bằng `python src/processing/run.py`):
    1. clean.py          — strip HTML/markdown, normalize timestamps & severity
    2. (lang detect)     — lingua language-detector
    3. dedup.py          — MinHash + LSH near-duplicate clustering
    4. report_builder.py — build STIX 2.1 Report SDO per (canonical) article
    5. schema.py         — persist STIX objects sang DB
"""
