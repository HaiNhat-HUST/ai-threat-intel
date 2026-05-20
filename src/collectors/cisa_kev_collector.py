"""
collectors/cisa_kev_collector.py

Thu thập CISA Known Exploited Vulnerabilities (KEV) Catalog.
Đây là danh sách các CVE đang BỊ KHAI THÁC THỰC TẾ theo xác nhận của CISA —
cực kỳ có giá trị cho threat intel vì đây là lỗ hổng analyst cần patch ngay.

Endpoint công khai, không cần API key:
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Tài liệu: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""
import httpx
from datetime import datetime
from models import ThreatArticle, get_session, compute_hash
import config

CISA_KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"

def _fetch_kev_catalog() -> list[dict]:
    """Tải toàn bộ KEV catalog từ CISA."""
    try:
        resp = httpx.get(
            CISA_KEV_URL,
            timeout=30,
            headers={"User-Agent": "LLM-CTI-Collector/1.0"},
            follow_redirects=True,
        )
        if resp.status_code == 200:
            return resp.json().get("vulnerabilities", [])
        print(f"  [CISA KEV] HTTP {resp.status_code}")
    except Exception as e:
        print(f"  [CISA KEV] Error: {e}")
    return []


def collect_cisa_kev(limit: int | None = None, recent_only: bool = True):
    """
    Thu thập CISA KEV và lưu vào DB.

    Args:
        limit:       Số entry tối đa (default: config.CISA_KEV_LIMIT hoặc 100).
                     KEV catalog hiện có ~1200 entries; nên dùng recent_only=True
                     trong vận hành bình thường để tránh nhập cả catalog.
        recent_only: Nếu True, chỉ lưu những entry chưa có trong DB (incremental).
                     Nếu False, cố gắng nhập toàn bộ catalog (dùng cho seed ban đầu).
    """
    limit   = limit or getattr(config, "CISA_KEV_LIMIT", 100)
    session = get_session()
    total_new = 0

    print("[CISA KEV] Đang tải Known Exploited Vulnerabilities catalog...")
    vulns = _fetch_kev_catalog()
    if not vulns:
        session.close()
        return

    print(f"  [CISA KEV] Catalog có {len(vulns)} entries — xử lý tối đa {limit}")

    # Sắp xếp theo dateAdded mới nhất trước
    def parse_date(v: dict) -> datetime:
        try:
            return datetime.strptime(v.get("dateAdded", "1970-01-01"), "%Y-%m-%d")
        except Exception:
            return datetime.min

    vulns_sorted = sorted(vulns, key=parse_date, reverse=True)

    for vuln in vulns_sorted[:limit]:
        cve_id       = vuln.get("cveID", "")
        vendor       = vuln.get("vendorProject", "")
        product      = vuln.get("product", "")
        vuln_name    = vuln.get("vulnerabilityName", "")
        date_added   = vuln.get("dateAdded", "")
        due_date     = vuln.get("dueDate", "")          # deadline patch cho gov agencies
        description  = vuln.get("shortDescription", "")
        action       = vuln.get("requiredAction", "")
        notes        = vuln.get("notes", "")

        content = (
            f"[CISA KEV] {cve_id} — {vuln_name}\n"
            f"Vendor/Product: {vendor} / {product}\n"
            f"Date Added to KEV: {date_added}\n"
            f"Patch Due Date:    {due_date}\n"
            f"\nDescription:\n{description}\n"
            f"\nRequired Action:\n{action}\n"
        )
        if notes:
            content += f"\nNotes:\n{notes}\n"

        content_hash = compute_hash(content)
        if session.query(ThreatArticle).filter_by(content_hash=content_hash).first():
            # Đã có — nếu recent_only thì dừng sớm (catalog sorted mới → cũ)
            if recent_only:
                break
            continue

        try:
            pub_date = datetime.strptime(date_added, "%Y-%m-%d")
        except Exception:
            pub_date = datetime.utcnow()

        session.add(ThreatArticle(
            title=f"KEV: {cve_id} — {vuln_name[:150]}",
            source="CISA KEV",
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            raw_content=content,
            content_hash=content_hash,
            severity="CRITICAL",   # Tất cả KEV đều là lỗ hổng đang bị exploit → CRITICAL
            published_at=pub_date,
        ))
        total_new += 1
        print(f"  [KEV] {cve_id} — {vuln_name[:55]} (added {date_added})")

    session.commit()
    session.close()
    print(f"\n✅ CISA KEV: Đã lưu {total_new} entry mới")
