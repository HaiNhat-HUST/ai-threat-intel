"""Unit tests cho dedup.py - MinHash + LSH clustering."""
from processing.dedup import find_clusters


def test_empty_input_returns_empty():
    assert find_clusters([]) == []


def test_singletons_when_all_unique():
    items = [
        (1, "completely different content about cryptocurrency mining"),
        (2, "another totally distinct article on Linux kernel updates"),
        (3, "yet another unrelated topic discussing reverse engineering"),
    ]
    clusters = find_clusters(items, threshold=0.85)
    assert len(clusters) == 3
    assert all(len(c) == 1 for c in clusters)


def test_near_duplicates_get_clustered():
    base = ("Critical vulnerability discovered in Microsoft Exchange Server "
            "allowing remote code execution via crafted email messages "
            "according to security researchers worldwide today.")
    items = [
        (1, base),
        (2, base + " Additional context here."),     # near-dup of 1
        (3, "Totally unrelated content about Python web frameworks and Django."),
    ]
    clusters = find_clusters(items, threshold=0.5)
    # Expect 2 clusters: {1,2}, {3}
    assert len(clusters) == 2
    multi = [c for c in clusters if len(c) > 1]
    assert len(multi) == 1
    assert set(multi[0]) == {1, 2}


def test_canonical_is_smallest_id_in_cluster():
    """cluster[0] phai la id nho nhat (= bai cu nhat)."""
    txt = "Apache HTTPD critical vulnerability allows attackers remote shell access via crafted request."
    items = [(5, txt), (2, txt), (10, txt)]
    clusters = find_clusters(items, threshold=0.5)
    multi = [c for c in clusters if len(c) > 1]
    assert len(multi) == 1
    assert multi[0][0] == 2     # canonical = smallest id
