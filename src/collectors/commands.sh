# ============================================================
# TEST COMMANDS — Layer 1 Collectors
# ============================================================
# Cấu trúc thư mục thực tế:
#   collectors_updated/
#   └── collectors/
#       ├── config.py
#       ├── models.py
#       ├── requirements.txt
#       ├── nvd_collector.py
#       ├── rss_collector.py
#       ├── reddit_collector.py
#       ├── otx_collector.py
#       ├── abusech_collector.py
#       ├── cisa_kev_collector.py
#       └── github_collector.py
#
# Tất cả lệnh chạy từ bên trong folder collectors/:
#   cd D:\code\collectors_updated\collectors
# ============================================================


# ------------------------------------------------------------
# 0. SETUP — chạy 1 lần trước khi test
# ------------------------------------------------------------

cd D:\code\collectors_updated\collectors

# Cài dependencies
uv add -r requirements.txt

# Tạo DB schema
uv run python -c "from models import Base, engine; Base.metadata.create_all(engine); print('DB OK')"


# ------------------------------------------------------------
# 1. NVD COLLECTOR
# ------------------------------------------------------------

# Test mặc định
uv run python -c "from nvd_collector import collect_nvd; collect_nvd()"

# ------------------------------------------------------------
# 2. RSS COLLECTOR
# ------------------------------------------------------------

uv run python -c "from rss_collector import collect_rss; collect_rss()"


# ------------------------------------------------------------
# 3. REDDIT COLLECTOR
# ------------------------------------------------------------

uv run python -c "from reddit_collector import collect_reddit; collect_reddit()"


# ------------------------------------------------------------
# 4. OTX COLLECTOR
# ------------------------------------------------------------

uv run python -c "from otx_collector import collect_otx; collect_otx()"

# ------------------------------------------------------------
# 5. ABUSE.CH COLLECTOR
# ------------------------------------------------------------

# Chạy cả 3 feed
uv run python -c "from abusech_collector import collect_abusech; collect_abusech()"

# ------------------------------------------------------------
# 6. CISA KEV COLLECTOR
# ------------------------------------------------------------

#chỉ lấy entries mới
uv run python -c "from cisa_kev_collector import collect_cisa_kev; collect_cisa_kev()"


# ------------------------------------------------------------
# 7. GITHUB COLLECTOR
# ------------------------------------------------------------

uv run python -c "from github_collector import collect_github_advisories; collect_github_advisories()"

# ------------------------------------------------------------
# 8. CHẠY TẤT CẢ
# ------------------------------------------------------------

uv run python -c "
from nvd_collector      import collect_nvd
from rss_collector      import collect_rss
from reddit_collector   import collect_reddit
from otx_collector      import collect_otx
from abusech_collector  import collect_abusech
from cisa_kev_collector import collect_cisa_kev
from github_collector   import collect_github_advisories

collect_cisa_kev()
collect_nvd()
collect_abusech()
collect_otx()
collect_rss()
collect_github_advisories()
collect_reddit()
print('Done')
"

# ------------------------------------------------------------
# 9. CHẠY FILE MAIN.PY
# ------------------------------------------------------------

uv run python main.py