"""
dedup.py — Near-duplicate detection bằng MinHash + LSH.

Vì sao MinHash thay vì SHA-256:
    Layer 1 đã hash exact bằng `content_hash` (SHA-256), nên 90/90 row đều
    UNIQUE. Nhưng cùng một sự kiện (vd: "Grafana breach") thường được
    Hacker News, Threatpost, Reddit cùng đăng — TEXT khác nhau nhưng
    NỘI DUNG trùng. Đây là near-duplicate — MinHash + LSH bắt được.

Thuật toán:
    1. Shingle text thành tập k-gram (5 từ liên tiếp, lowercase).
    2. MinHash mỗi tập shingles (128 permutations).
    3. LSH index → query → các bài Jaccard ≥ threshold.
    4. Union-Find để gom thành cluster.

Public API:
    find_clusters(items, threshold=0.85) -> list[list[int]]
        items: list of (id, clean_text)
        return: list các cluster, mỗi cluster là list id
                (id đầu tiên trong cluster là canonical/representative)
"""
from __future__ import annotations

import re
from typing import Iterable

from datasketch import MinHash, MinHashLSH

_TOKEN_RE = re.compile(r"\w+", re.UNICODE)

_NUM_PERM = 128       # số permutation cho MinHash — 128 là default cân bằng
_SHINGLE_K = 5        # số từ trong 1 shingle
_DEFAULT_THRESHOLD = 0.85   # Jaccard ≥ 0.85 → coi là near-duplicate


def _shingles(text: str, k: int = _SHINGLE_K) -> set[str]:
    tokens = _TOKEN_RE.findall(text.lower())
    if len(tokens) < k:
        # Văn bản quá ngắn → mỗi token là 1 "shingle" để vẫn có MinHash dùng được
        return set(tokens)
    return {" ".join(tokens[i:i + k]) for i in range(len(tokens) - k + 1)}


def _minhash(text: str) -> MinHash:
    mh = MinHash(num_perm=_NUM_PERM)
    for sh in _shingles(text):
        mh.update(sh.encode("utf-8"))
    return mh


def find_clusters(
    items: Iterable[tuple[int, str]],
    threshold: float = _DEFAULT_THRESHOLD,
) -> list[list[int]]:
    """
    Trả về list các cluster (mỗi cluster ≥ 1 id).
    id đầu tiên trong cluster = canonical (lấy id nhỏ nhất = bài cũ nhất).
    """
    items = list(items)
    if not items:
        return []

    lsh = MinHashLSH(threshold=threshold, num_perm=_NUM_PERM)
    mhs: dict[int, MinHash] = {}
    for id_, text in items:
        mh = _minhash(text)
        mhs[id_] = mh
        # LSH key phải là string
        lsh.insert(str(id_), mh)

    # Union-Find / Disjoint Set Union
    parent: dict[int, int] = {id_: id_ for id_, _ in items}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            # Giữ id nhỏ hơn làm gốc (canonical)
            if ra < rb:
                parent[rb] = ra
            else:
                parent[ra] = rb

    for id_, _ in items:
        for hit_str in lsh.query(mhs[id_]):
            hit = int(hit_str)
            if hit != id_:
                union(id_, hit)

    clusters: dict[int, list[int]] = {}
    for id_, _ in items:
        root = find(id_)
        clusters.setdefault(root, []).append(id_)

    # Trong mỗi cluster, đảm bảo canonical (id nhỏ nhất) ở vị trí 0
    out: list[list[int]] = []
    for root, members in clusters.items():
        members_sorted = sorted(members)
        out.append(members_sorted)
    # Sắp xếp các cluster theo canonical id để output ổn định
    out.sort(key=lambda c: c[0])
    return out
