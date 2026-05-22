"""
collectors/abusech_collector.py

Thu thập IOC và threat data từ 3 feed của Abuse.ch:
  - URLhaus   : URLs phát tán malware (https://urlhaus.abuse.ch)
  - MalwareBazaar: Samples malware với metadata (https://bazaar.abuse.ch)
  - ThreatFox : IOC đa loại: IP, domain, URL, hash (https://threatfox.abuse.ch)

Tất cả đều là public API, không cần API key.
Tham khảo: https://abuse.ch/blog/api-documentation/
"""
import os
import httpx
import time
from datetime import datetime
from models import ThreatArticle, get_session, compute_hash
import config

from dotenv import load_dotenv

load_dotenv()

# 
# URLHAUS
# 

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/"


def _collect_urlhaus(session, limit: int) -> int:
    """
    Lấy URLs phát tán malware mới nhất từ URLhaus.
    Endpoint: POST /urls/recent/ — trả về 10 URL mới nhất mỗi lần.
    """
    total_new = 0
    print("[URLhaus] Thu thập URLs mới...")

    # URLhaus trả tối đa 10 kết quả/request; gọi nhiều lần nếu cần
    batches_needed = max(1, limit // 10)
    collected: list[dict] = []

    for _ in range(min(batches_needed, 5)):   # giới hạn 5 request ~ 50 URLs
        try:
            resp = httpx.post(
                URLHAUS_API + "urls/recent/",
                data={"query": "get_urls", "limit": 10},
                timeout=20,
                headers={
                    "User-Agent": "LLM-CTI-Collector/1.0",
                    "Auth-Key": os.getenv("ABUSECH_API_KEY"),   # thêm dòng này
                },
            )
            if resp.status_code != 200:
                print(f"  [URLhaus] HTTP {resp.status_code}")
                break
            data = resp.json()
            if data.get("query_status") != "is_recent":
                break
            urls = data.get("urls", [])
            if not urls:
                break
            collected.extend(urls)
            time.sleep(1)
        except Exception as e:
            print(f"  [URLhaus] Error: {e}")
            break

    for entry in collected[:limit]:
        url_val  = entry.get("url", "")
        url_id   = entry.get("id", "")
        threat   = entry.get("threat", "")
        tags     = ", ".join(entry.get("tags") or [])
        reporter = entry.get("reporter", "")
        status   = entry.get("url_status", "")

        content = (
            f"[URLhaus] Malware URL\n"
            f"URL: {url_val}\n"
            f"Threat: {threat}\n"
            f"Status: {status}\n"
            f"Reporter: {reporter}\n"
        )
        if tags:
            content += f"Tags: {tags}\n"

        content_hash = compute_hash(content)
        if session.query(ThreatArticle).filter_by(content_hash=content_hash).first():
            continue

        try:
            pub_date = datetime.strptime(
                entry.get("date_added", "")[:19], "%Y-%m-%d %H:%M:%S"
            )
        except Exception:
            pub_date = datetime.utcnow()

        session.add(ThreatArticle(
            title=f"URLhaus: {url_val[:200]}",
            source="Abuse.ch URLhaus",
            url=f"https://urlhaus.abuse.ch/url/{url_id}/",
            raw_content=content,
            content_hash=content_hash,
            severity="HIGH",
            published_at=pub_date,
        ))
        total_new += 1
        print(f"  [URL] {url_val[:70]} — {threat}")

    return total_new


# 
# MALWAREBAZAAR
# 

BAZAAR_API = "https://mb-api.abuse.ch/api/v1/"


def _collect_malwarebazaar(session, limit: int) -> int:
    """
    Lấy malware samples mới nhất từ MalwareBazaar.
    Endpoint: POST với query=get_recent — trả về 100 samples mới nhất.
    """
    total_new = 0
    print("[MalwareBazaar] Thu thập samples mới...")

    try:
        resp = httpx.post(
            BAZAAR_API,
            data={"query": "get_recent", "selector": "time"},
            timeout=30,
            headers={
                "User-Agent": "LLM-CTI-Collector/1.0",
                "Auth-Key": os.getenv("ABUSECH_API_KEY"),   # thêm dòng này
            },
        )
        if resp.status_code != 200:
            print(f"  [MalwareBazaar] HTTP {resp.status_code}")
            return 0
        data = resp.json()
        if data.get("query_status") != "ok":
            print(f"  [MalwareBazaar] Status: {data.get('query_status')}")
            return 0
        samples = data.get("data", [])[:limit]
    except Exception as e:
        print(f"  [MalwareBazaar] Error: {e}")
        return 0

    for sample in samples:
        sha256     = sample.get("sha256_hash", "")
        md5        = sample.get("md5_hash", "")
        file_name  = sample.get("file_name", "")
        file_type  = sample.get("file_type", "")
        
        tags_list  = sample.get("tags") or []
        malware_family = sample.get("signature") or (tags_list[0] if tags_list else "")
        
        reporter   = sample.get("reporter", "")
        tags       = ", ".join(sample.get("tags") or [])

        content = (
            f"[MalwareBazaar] Sample\n"
            f"SHA256: {sha256}\n"
            f"MD5:    {md5}\n"
            f"File:   {file_name} ({file_type})\n"
            f"Family: {malware_family}\n"
            f"Reporter: {reporter}\n"
        )
        if tags:
            content += f"Tags: {tags}\n"

        content_hash = compute_hash(content)
        if session.query(ThreatArticle).filter_by(content_hash=content_hash).first():
            continue

        try:
            pub_date = datetime.strptime(
                sample.get("first_seen", "")[:19], "%Y-%m-%d %H:%M:%S"
            )
        except Exception:
            pub_date = datetime.utcnow()

        session.add(ThreatArticle(
            title=f"MalwareBazaar: {malware_family or file_name or sha256[:16]}",
            source="Abuse.ch MalwareBazaar",
            url=f"https://bazaar.abuse.ch/sample/{sha256}/",
            raw_content=content,
            content_hash=content_hash,
            severity="HIGH",
            published_at=pub_date,
        ))
        total_new += 1
        print(f"  [SAMPLE] {(malware_family or file_name)[:50]} — {sha256[:16]}...")

    return total_new


# 
# THREATFOX
# 

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"


def _collect_threatfox(session, limit: int) -> int:
    """
    Lấy IOC mới nhất từ ThreatFox (IP, domain, URL, hash).
    Endpoint: POST với query=get_iocs — không cần API key.
    """
    total_new = 0
    print("[ThreatFox] Thu thập IOCs mới...")

    try:
        resp = httpx.post(
            THREATFOX_API,
            json={"query": "get_iocs", "days": getattr(config, "ABUSECH_DAYS_BACK", 3)},
            timeout=30,
            headers={
                "User-Agent": "LLM-CTI-Collector/1.0",
                "Content-Type": "application/json",
                "Auth-Key": os.getenv("ABUSECH_API_KEY"),
            },
        )
        if resp.status_code != 200:
            print(f"  [ThreatFox] HTTP {resp.status_code}")
            return 0
        data = resp.json()
        if data.get("query_status") != "ok":
            print(f"  [ThreatFox] Status: {data.get('query_status')}")
            return 0
        iocs = data.get("data", [])[:limit]
    except Exception as e:
        print(f"  [ThreatFox] Error: {e}")
        return 0

    for ioc in iocs:
        ioc_val    = ioc.get("ioc", "")
        ioc_type   = ioc.get("ioc_type", "")
        threat_type = ioc.get("threat_type", "")
        malware    = ioc.get("malware", "") or ioc.get("malware_printable", "")
        confidence = ioc.get("confidence_level", 0)
        reporter   = ioc.get("reporter", "")
        tags       = ", ".join(ioc.get("tags") or [])
        refs       = "\n".join((ioc.get("reference") or "").splitlines()[:3])

        content = (
            f"[ThreatFox] IOC\n"
            f"IOC:        {ioc_val}\n"
            f"Type:       {ioc_type}\n"
            f"Threat:     {threat_type}\n"
            f"Malware:    {malware}\n"
            f"Confidence: {confidence}%\n"
            f"Reporter:   {reporter}\n"
        )
        if tags:
            content += f"Tags: {tags}\n"
        if refs:
            content += f"References:\n{refs}\n"

        content_hash = compute_hash(content)
        if session.query(ThreatArticle).filter_by(content_hash=content_hash).first():
            continue

        try:
            pub_date = datetime.strptime(
                ioc.get("first_seen", "")[:19], "%Y-%m-%d %H:%M:%S"
            )
        except Exception:
            pub_date = datetime.utcnow()

        # Mức severity theo confidence
        severity = "HIGH" if confidence >= 75 else "MEDIUM" if confidence >= 50 else "LOW"

        session.add(ThreatArticle(
            title=f"ThreatFox [{ioc_type}]: {ioc_val[:150]}",
            source="Abuse.ch ThreatFox",
            url=f"https://threatfox.abuse.ch/ioc/{ioc.get('id', '')}/",
            raw_content=content,
            content_hash=content_hash,
            severity=severity,
            published_at=pub_date,
        ))
        total_new += 1
        print(f"  [IOC/{ioc_type}] {ioc_val[:60]} — {malware or threat_type}")

    return total_new


# 
# PUBLIC INTERFACE
# 

def collect_abusech(limit: int | None = None):
    """
    Thu thập từ cả 3 feed Abuse.ch: URLhaus, MalwareBazaar, ThreatFox.

    Args:
        limit: Số bản ghi tối đa mỗi feed (default: config.ABUSECH_LIMIT hoặc 50)
    """
    limit   = limit or getattr(config, "ABUSECH_LIMIT", 50)
    session = get_session()
    total   = 0

    total += _collect_urlhaus(session, limit)
    session.commit()

    total += _collect_malwarebazaar(session, limit)
    session.commit()

    total += _collect_threatfox(session, limit)
    session.commit()

    session.close()
    print(f"\n✅ Abuse.ch (URLhaus + MalwareBazaar + ThreatFox): Đã lưu {total} bản ghi mới")
