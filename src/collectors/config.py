# ============================================================
# config.py — Cấu hình toàn bộ Layer 1 Collectors
# ============================================================

# 
# DATABASE
# 

# SQLAlchemy connection string
# SQLite (mặc định, không cần cài thêm):
DATABASE_URL = "sqlite:///threat_intel.db"

# PostgreSQL (dùng khi chuyển sang production):
# DATABASE_URL = "postgresql://user:password@localhost:5432/threat_intel"

# 
# NVD / CVE  (nvd_collector.py)
# 

# Số ngày nhìn lại để lấy CVE mới
NVD_DAYS_BACK = 3

# Số CVE tối đa mỗi lần fetch (NVD giới hạn 2000/request)
NVD_MAX_CVES = 10

# 
# RSS FEEDS  (rss_collector.py)
# 

# Số bài tối đa lấy từ mỗi feed RSS
RSS_ARTICLES_PER_FEED = 5

# 
# REDDIT  (reddit_collector.py)
# 

# Số posts tối đa lấy từ mỗi subreddit mỗi lần chạy
REDDIT_POSTS_PER_SUB = 5

# 
# ALIENVAULT OTX  (otx_collector.py)
# 

# Số ngày nhìn lại để lấy pulses mới/cập nhật
OTX_DAYS_BACK = 3

# Số pulse tối đa mỗi lần fetch
OTX_LIMIT = 10

# 
# ABUSE.CH  (abusech_collector.py)
# 

# Số bản ghi tối đa mỗi feed (URLhaus / MalwareBazaar / ThreatFox)
ABUSECH_LIMIT = 10

# Số ngày nhìn lại cho ThreatFox IOC query
ABUSECH_DAYS_BACK = 3

# 
# CISA KEV  (cisa_kev_collector.py)
# 

# Số entry KEV tối đa xử lý mỗi lần chạy
# Chạy lần đầu nên tăng lên ~2000 để seed toàn bộ catalog (~1200 entries)
# Các lần sau để 50–100 là đủ (chỉ lấy entries mới)
CISA_KEV_LIMIT = 10

# 
# GITHUB SECURITY ADVISORIES  (github_collector.py)
# 

# Số advisory tối đa mỗi lần fetch (GitHub API giới hạn 100/request)
GITHUB_ADVISORIES_LIMIT = 10