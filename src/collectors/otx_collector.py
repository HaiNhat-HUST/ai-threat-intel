"""
collectors/otx_collector.py

Thu thập Indicators of Compromise (IOC) từ AlienVault OTX (Open Threat Exchange).
Sử dụng OTX DirectConnect API — miễn phí, chỉ cần tạo account tại otx.alienvault.com.

Các feed được thu thập:
- Subscribed pulses (feed cá nhân hóa theo các topic bạn follow)
- Modified pulses (toàn bộ pulse mới/cập nhật gần đây — fallback khi không có key)

Cài thư viện: uv add OTXv2
Hoặc dùng httpx trực tiếp (không cần cài thêm) — script này dùng httpx để không phụ thuộc.
"""
import os
import httpx
import time
from datetime import datetime, timedelta
from models import ThreatArticle, get_session, compute_hash
import config
from dotenv import load_dotenv

load_dotenv()

OTX_BASE = "https://otx.alienvault.com/api/v1"


def _get_headers() -> dict:
    #api_key = getattr(config, "OTX_API_KEY", "")
    api_key=os.getenv("OTX_API_KEY")
    headers = {"User-Agent": "LLM-CTI-Collector/1.0"}
    if api_key:
        headers["X-OTX-API-KEY"] = api_key
    return headers


def _fetch_subscribed_pulses(since_days: int, limit: int) -> list[dict]:
    """
    Lấy pulses từ feed cá nhân hóa (cần API key).
    Trả về list pulse dict.
    """
    since = (datetime.utcnow() - timedelta(days=since_days)).strftime(
        "%Y-%m-%dT%H:%M:%S"
    )
    url = f"{OTX_BASE}/pulses/subscribed"
    params = {"limit": limit, "modified_since": since}
    try:
        resp = httpx.get(
            url, headers=_get_headers(), params=params, timeout=30, follow_redirects=True
        )
        if resp.status_code == 200:
            return resp.json().get("results", [])
        print(f"  [OTX/subscribed] HTTP {resp.status_code}")
    except Exception as e:
        print(f"  [OTX/subscribed] Error: {e}")
    return []


def _fetch_recent_pulses(since_days: int, limit: int) -> list[dict]:
    """
    Lấy pulses mới/cập nhật gần đây (public endpoint — không cần key).
    Fallback khi không có API key hoặc subscribed feed trống.
    """
    modified_since = (datetime.utcnow() - timedelta(days=since_days)).strftime(
        "%Y-%m-%dT%H:%M:%S"
    )
    url = f"{OTX_BASE}/pulses/activity"
    params = {"limit": limit, "modified_since": modified_since}
    try:
        resp = httpx.get(
            url, headers=_get_headers(), params=params, timeout=30, follow_redirects=True
        )
        if resp.status_code == 200:
            return resp.json().get("results", [])
        print(f"  [OTX/activity] HTTP {resp.status_code}")
    except Exception as e:
        print(f"  [OTX/activity] Error: {e}")
    return []


def _pulse_to_content(pulse: dict) -> str:
    """Chuyển pulse dict → chuỗi nội dung có cấu trúc để lưu vào DB."""
    name        = pulse.get("name", "")
    description = pulse.get("description", "").strip()
    author      = pulse.get("author_name", "")
    tags        = ", ".join(pulse.get("tags", [])[:15])
    tlp         = pulse.get("tlp", "white").upper()
    references  = "\n".join(pulse.get("references", [])[:5])

    # Thống kê IOC
    indicators = pulse.get("indicators", [])
    ioc_summary_parts = []
    ioc_by_type: dict[str, list[str]] = {}
    for ind in indicators[:50]:          # giới hạn 50 IOC đầu để tránh quá dài
        t   = ind.get("type", "unknown")
        val = ind.get("indicator", "")
        ioc_by_type.setdefault(t, []).append(val)
    for ioc_type, vals in ioc_by_type.items():
        sample = ", ".join(vals[:5])
        ioc_summary_parts.append(f"  {ioc_type} ({len(vals)}): {sample}")
    ioc_text = "\n".join(ioc_summary_parts) if ioc_summary_parts else "  (no indicators)"

    lines = [
        f"[OTX Pulse] {name}",
        f"Author: {author} | TLP: {tlp}",
    ]
    if tags:
        lines.append(f"Tags: {tags}")
    if description:
        lines.append(f"\nDescription:\n{description[:2000]}")
    lines.append(f"\nIOCs ({len(indicators)} total):\n{ioc_text}")
    if references:
        lines.append(f"\nReferences:\n{references}")

    return "\n".join(lines)


def collect_otx(since_days: int | None = None, limit: int | None = None):
    """
    Thu thập OTX pulses và lưu vào DB.

    Args:
        since_days: Số ngày nhìn lại (default: config.OTX_DAYS_BACK hoặc 7)
        limit:      Số pulse tối đa mỗi lần fetch (default: config.OTX_LIMIT hoặc 50)
    """
    since_days = since_days or getattr(config, "OTX_DAYS_BACK", 7)
    limit      = limit      or getattr(config, "OTX_LIMIT", 50)
    api_key    = getattr(config, "OTX_API_KEY", "")

    session   = get_session()
    total_new = 0

    print(f"[OTX] Thu thập pulses ({since_days} ngày gần nhất)...")

    # Thử subscribed feed trước (cần key), rồi fallback sang activity feed
    pulses = []
    if api_key:
        pulses = _fetch_subscribed_pulses(since_days, limit)
        print(f"  [OTX/subscribed] {len(pulses)} pulses")

    if not pulses:
        pulses = _fetch_recent_pulses(since_days, limit)
        print(f"  [OTX/activity] {len(pulses)} pulses")

    for pulse in pulses:
        pulse_id  = pulse.get("id", "")
        name      = pulse.get("name", "").strip()
        if not name:
            continue

        content      = _pulse_to_content(pulse)
        content_hash = compute_hash(content)

        if session.query(ThreatArticle).filter_by(content_hash=content_hash).first():
            continue

        try:
            pub_date = datetime.strptime(
                pulse.get("created", "")[:19], "%Y-%m-%dT%H:%M:%S"
            )
        except Exception:
            pub_date = datetime.utcnow()

        # Mức độ nghiêm trọng dựa trên TLP (heuristic đơn giản)
        tlp      = pulse.get("tlp", "white").lower()
        severity = {"red": "HIGH", "amber": "MEDIUM", "green": "LOW", "white": "LOW"}.get(
            tlp, "Unknown"
        )

        session.add(ThreatArticle(
            title=name[:500],
            source="AlienVault OTX",
            url=f"https://otx.alienvault.com/pulse/{pulse_id}",
            raw_content=content,
            content_hash=content_hash,
            severity=severity,
            published_at=pub_date,
        ))
        total_new += 1
        print(f"  [PULSE] {name[:60]}")
        time.sleep(0.1)   # nhẹ nhàng với API

    session.commit()
    session.close()
    print(f"✅ OTX: Đã lưu {total_new} pulse mới")
