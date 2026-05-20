import httpx
from datetime import datetime, timedelta
from models import ThreatArticle, get_session, compute_hash
import config

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def collect_nvd(days_back: int | None = None):
    """Lấy CVE mới trong N ngày gần nhất"""
    if days_back is None:
        days_back = config.NVD_DAYS_BACK
    session = get_session()

    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days_back)

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate":   end_date.strftime("%Y-%m-%dT23:59:59.999"),
        "resultsPerPage": config.NVD_MAX_CVES,
    }
    
    print(f"[NVD] Lấy CVE từ {start_date.date()} đến {end_date.date()}")
    
    try:
        response = httpx.get(NVD_API_URL, params=params, timeout=30)
        data = response.json()
    except Exception as e:
        print(f"[ERROR] NVD API: {e}")
        return

    total_new = 0
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        
        # Lấy mô tả tiếng Anh
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d["lang"] == "en"), ""
        )
        
        # Lấy CVSS score
        severity = "Unknown"
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            score = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
            severity = score
        elif "cvssMetricV2" in metrics:
            score = metrics["cvssMetricV2"][0]["baseSeverity"]
            severity = score

        content = f"CVE ID: {cve_id}\n\nDescription: {description}"
        content_hash = compute_hash(content)
        
        exists = session.query(ThreatArticle).filter_by(
            content_hash=content_hash
        ).first()
        if exists:
            continue

        article = ThreatArticle(
            title=cve_id,
            source="NVD",
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            raw_content=content,
            content_hash=content_hash,
            severity=severity,
            published_at=datetime.utcnow()
        )
        session.add(article)
        total_new += 1
        print(f"  [CVE] {cve_id} — {severity}")

    session.commit()
    session.close()
    print(f"✅ NVD: Đã lưu {total_new} CVE mới")