"""
collectors/github_collector.py

Thu thập GitHub Security Advisories (GHSA) qua public REST API.
Không cần authentication — endpoint hoàn toàn public.

Tài liệu: https://docs.github.com/en/rest/security-advisories/global-advisories
"""
import httpx
from datetime import datetime
from models import ThreatArticle, get_session, compute_hash
import config

GITHUB_API_URL = "https://api.github.com/advisories"
HEADERS = {
    "User-Agent": "LLM-CTI-Collector/1.0",
    "Accept": "application/vnd.github+json",
}


def collect_github_advisories(limit: int | None = None):
    """Thu thập GitHub Security Advisories qua public REST API (không cần auth)."""
    limit     = limit or config.GITHUB_ADVISORIES_LIMIT
    session   = get_session()
    total_new = 0

    print("[GitHub] Thu thập Security Advisories...")
    try:
        resp = httpx.get(
            GITHUB_API_URL,
            headers=HEADERS,
            params={"per_page": limit, "type": "reviewed"},
            timeout=20,
        )
        if resp.status_code != 200:
            print(f"  [WARN] GitHub Advisories: HTTP {resp.status_code}")
            session.close()
            return

        for adv in resp.json():
            ghsa_id     = adv.get("ghsa_id", "")
            summary     = adv.get("summary", "")
            description = adv.get("description", "")
            severity    = adv.get("severity", "unknown").title()
            adv_url     = adv.get("html_url", "")
            cve_id      = adv.get("cve_id", "")

            vulns    = adv.get("vulnerabilities", [])
            packages = ", ".join(
                f"{v.get('package', {}).get('ecosystem', '')}/{v.get('package', {}).get('name', '')}"
                for v in vulns[:3] if v.get("package")
            )

            content = (
                f"GHSA ID: {ghsa_id}\nCVE: {cve_id}\n"
                f"Summary: {summary}\nSeverity: {severity}\n"
            )
            if packages:
                content += f"Affected packages: {packages}\n"
            if description:
                content += f"\nDescription:\n{description[:2000]}"

            content_hash = compute_hash(content)
            if session.query(ThreatArticle).filter_by(content_hash=content_hash).first():
                continue

            try:
                pub_date = datetime.strptime(
                    adv.get("published_at", "")[:19], "%Y-%m-%dT%H:%M:%S"
                )
            except Exception:
                pub_date = datetime.utcnow()

            session.add(ThreatArticle(
                title=f"{ghsa_id}: {summary[:200]}",
                source="GitHub Advisories",
                url=adv_url,
                raw_content=content,
                content_hash=content_hash,
                severity=severity,
                published_at=pub_date,
            ))
            total_new += 1
            print(f"  [GHSA] {ghsa_id} ({severity}) — {summary[:50]}")

    except Exception as e:
        print(f"  [ERROR] GitHub Advisories: {e}")

    session.commit()
    session.close()
    print(f"\n✅ GitHub Advisories: Đã lưu {total_new} advisory mới")
