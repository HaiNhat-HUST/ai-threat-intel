"""
main.py — Tạo DB schema và chạy tất cả collectors.
Đặt file này trong folder collectors/ rồi chạy: python main.py
"""
import sys
import os
from models import Base, engine
from nvd_collector      import collect_nvd
from rss_collector      import collect_rss
from reddit_collector   import collect_reddit
from otx_collector      import collect_otx
from abusech_collector  import collect_abusech
from cisa_kev_collector import collect_cisa_kev
from github_collector   import collect_github_advisories
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv()

if __name__ == "__main__":
    print("Tạo schema...")
    Base.metadata.create_all(bind=engine)

    for name, fn in [
        ("NVD",    collect_nvd),
        ("RSS",    collect_rss),
        ("Reddit", collect_reddit),
        ("OTX",    collect_otx),
        ("AbuseC", collect_abusech),
        ("CISA",   collect_cisa_kev),
        ("GitHub", collect_github_advisories),
    ]:
        print(f"\n--- {name} ---")
        try:
            fn()
        except Exception as e:
            print(f"[ERROR] {name}: {e}")