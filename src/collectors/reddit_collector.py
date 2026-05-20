"""
collectors/reddit_collector.py

Thu thập Reddit posts qua Reddit public .json API + browser headers.
Không cần API key, không cần thư viện thêm.
"""
import httpx
import time
from datetime import datetime
from models import ThreatArticle, get_session, compute_hash
import config

HEADERS = {
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept":          "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Referer":         "https://www.reddit.com/",
}

SECURITY_SUBREDDITS = [
    "netsec", "cybersecurity", "malware", "blueteamsec",
    "threatintel", "ReverseEngineering", "netsecstudents",
    "AskNetsec", "hacking",
]

SECURITY_KEYWORDS = [
    "malware", "ransomware", "cve", "exploit", "vulnerability", "apt",
    "threat", "phishing", "attack", "breach", "hack", "ioc", "c2",
    "botnet", "zero-day", "0day", "payload", "stealer", "rat",
    "backdoor", "lateral", "persistence", "indicator", "compromise",
    "incident", "forensic", "reverse", "shellcode",
]


# 
# FETCH
# 

def _fetch_subreddit(subreddit: str, limit: int) -> list[dict]:
    """Lấy posts mới nhất từ một subreddit qua .json endpoint."""
    url = f"https://www.reddit.com/r/{subreddit}/new.json"
    try:
        resp = httpx.get(url, headers=HEADERS,
                         params={"limit": limit, "raw_json": 1},
                         timeout=15, follow_redirects=True)
        if resp.status_code == 200:
            posts = resp.json().get("data", {}).get("children", [])
            return [p["data"] for p in posts if p.get("kind") == "t3"]
        print(f"  [WARN] r/{subreddit}: HTTP {resp.status_code}")
    except Exception as e:
        print(f"  [ERROR] r/{subreddit}: {e}")
    return []


# 
# DB HELPER
# 

def _save_post(post: dict, source_label: str, session) -> bool:
    """Chuyển post dict → ThreatArticle. Trả về True nếu lưu mới."""
    title    = (post.get("title") or "").strip()
    selftext = (post.get("selftext") or "").strip()
    score    = post.get("score", 0) or 0
    sub      = post.get("subreddit") or "unknown"
    author   = post.get("author") or "unknown"
    permalink = post.get("permalink") or ""
    flair    = post.get("link_flair_text") or ""

    if not title:
        return False

    # Lọc score thấp
    if score < 3:
        return False

    # Lọc nhanh bằng keyword
    combined = (title + " " + selftext).lower()
    if not any(kw in combined for kw in SECURITY_KEYWORDS):
        return False

    parts = [f"Title: {title}"]
    if selftext and selftext not in ("[removed]", "[deleted]"):
        parts.append(f"\nBody:\n{selftext[:2000]}")
    parts.append(f"\nSubreddit: r/{sub} | Score: {score} | Author: u/{author}")
    if flair:
        parts.append(f"Flair: {flair}")

    content      = "\n".join(parts)
    content_hash = compute_hash(content)

    if session.query(ThreatArticle).filter_by(content_hash=content_hash).first():
        return False

    created = post.get("created_utc")
    try:
        pub_date = datetime.utcfromtimestamp(float(created)) if created else datetime.utcnow()
    except Exception:
        pub_date = datetime.utcnow()

    full_url = (f"https://www.reddit.com{permalink}"
                if permalink and not permalink.startswith("http")
                else permalink or f"https://www.reddit.com/r/{sub}")

    session.add(ThreatArticle(
        title=title[:500],
        source=source_label,
        url=full_url,
        raw_content=content,
        content_hash=content_hash,
        published_at=pub_date,
    ))
    return True


# 
# PUBLIC INTERFACE
# 

def collect_reddit():
    """Thu thập Reddit posts qua Reddit .json API từ các subreddit bảo mật."""
    session   = get_session()
    total_new = 0
    limit     = config.REDDIT_POSTS_PER_SUB

    for sub in SECURITY_SUBREDDITS:
        print(f"[Reddit] r/{sub}")
        posts = _fetch_subreddit(sub, limit)
        print(f"  {len(posts)} posts từ API")
        time.sleep(1.5)

        for post in posts:
            if _save_post(post, f"Reddit/r/{sub}", session):
                total_new += 1
                print(f"  [NEW] {post.get('title', '')[:60]}")

    session.commit()
    session.close()
    print(f"\n✅ Reddit: Đã lưu {total_new} posts mới")