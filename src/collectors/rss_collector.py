import feedparser
import trafilatura
from datetime import datetime
from models import ThreatArticle, get_session, compute_hash
import config

# Danh sách các nguồn RSS uy tín
RSS_FEEDS = [
    {"name": "The Hacker News",   "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "Threatpost",        "url": "https://threatpost.com/feed/"},
    {"name": "SANS ISC",          "url": "https://isc.sans.edu/rssfeed_full.xml"},
    {"name": "Bleeping Computer", "url": "https://www.bleepingcomputer.com/feed/"},
]

def fetch_article_content(url: str) -> str:
    """Lấy nội dung bài viết từ URL, làm sạch HTML"""
    try:
        downloaded = trafilatura.fetch_url(url)
        content = trafilatura.extract(downloaded)
        return content or ""
    except Exception as e:
        print(f"[ERROR] Không lấy được nội dung: {url} — {e}")
        return ""

def collect_rss():
    session = get_session()
    total_new = 0

    for feed_info in RSS_FEEDS:
        print(f"[RSS] Đang thu thập: {feed_info['name']}")
        feed = feedparser.parse(feed_info["url"])

        for entry in feed.entries[:config.RSS_ARTICLES_PER_FEED]:
            url = entry.get("link", "")
            title = entry.get("title", "")

            # Lấy nội dung đầy đủ
            content = fetch_article_content(url)
            if not content:
                continue

            # Kiểm tra trùng lặp
            content_hash = compute_hash(content)
            exists = session.query(ThreatArticle).filter_by(
                content_hash=content_hash
            ).first()
            
            if exists:
                print(f"  [SKIP] Đã có: {title[:50]}")
                continue

            # Lưu vào DB
            article = ThreatArticle(
                title=title,
                source=feed_info["name"],
                url=url,
                raw_content=content,
                content_hash=content_hash,
                published_at=datetime(*entry.published_parsed[:6]) 
                             if hasattr(entry, "published_parsed") and entry.published_parsed 
                             else datetime.utcnow()
            )
            session.add(article)
            total_new += 1
            print(f"  [NEW] {title[:60]}")

    session.commit()
    session.close()
    print(f"\n✅ RSS: Đã lưu {total_new} bài mới")