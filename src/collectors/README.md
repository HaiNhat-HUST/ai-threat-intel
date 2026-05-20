# Threat Intel Collectors

Thu thập threat intelligence từ các nguồn: NVD, RSS, Reddit, AlienVault OTX, Abuse.ch, CISA KEV, GitHub Advisories.

## Cài đặt

1. Vào file .env   # điền OTX_API_KEY và ABUSECH_API_KEY


### Lấy API keys

**OTX_API_KEY** (AlienVault OTX)
1. Đăng ký tại https://otx.alienvault.com
2. Vào **Settings → API Key** → copy key

**ABUSECH_API_KEY** (Abuse.ch)
1. Đăng ký tại https://auth.abuse.ch
2. Vào **Account → API Key** → copy key

## Chạy

```bash
uv run python main.py
```

Dữ liệu được lưu vào `threat_intel.db` (SQLite). Schema tự động tạo khi chạy lần đầu.