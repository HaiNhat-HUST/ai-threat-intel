"""Unit tests cho clean.py - strip, normalize severity, infer severity, langdetect."""
from datetime import datetime, timezone

import pytest

from processing.clean import (
    clean_text, strip_html, strip_markdown,
    normalize_severity, infer_severity_from_content,
    to_utc, to_stix_timestamp,
    detect_language,
)


# ──────────────────────────────────────────────
# HTML / MARKDOWN STRIP
# ──────────────────────────────────────────────

def test_strip_html_removes_tags():
    out = strip_html("<p>hello <b>world</b></p>"); assert "hello" in out and "world" in out and "<" not in out


def test_strip_html_no_html_passthrough():
    assert strip_html("plain text no tags") == "plain text no tags"


def test_strip_markdown_keeps_code_content():
    """IOCs in code blocks must survive markdown stripping."""
    md = "### Title\n```py\n1.2.3.4\n```\nbody **bold**"
    out = strip_markdown(md)
    assert "1.2.3.4" in out          # IOC preserved
    assert "Title" in out            # header text kept
    assert "bold" in out             # bold text kept
    assert "###" not in out          # markdown markers stripped
    assert "```" not in out


def test_clean_text_collapses_whitespace():
    out = clean_text("hello   \t\t  world\n\n\n\nfoo")
    assert "   " not in out
    assert "\n\n\n" not in out


def test_clean_text_handles_empty():
    assert clean_text("") == ""
    assert clean_text(None) == ""    # type: ignore


# ──────────────────────────────────────────────
# SEVERITY NORMALIZATION
# ──────────────────────────────────────────────

@pytest.mark.parametrize("input_,expected", [
    ("CRITICAL", "critical"),
    ("Critical", "critical"),
    ("critical", "critical"),
    ("HIGH",     "high"),
    ("High",     "high"),
    ("MEDIUM",   "medium"),
    ("Moderate", "medium"),
    ("LOW",      "low"),
    ("INFO",     "info"),
    ("Informational", "info"),
    ("",         None),
    (None,       None),
    ("WAT",      None),
    ("unknown",  None),
])
def test_normalize_severity(input_, expected):
    assert normalize_severity(input_) == expected


# ──────────────────────────────────────────────
# SEVERITY INFERENCE
# ──────────────────────────────────────────────

def test_infer_kev_returns_critical():
    assert infer_severity_from_content("CISA KEV", "anything") == "critical"


def test_infer_kev_case_insensitive():
    assert infer_severity_from_content("cisa kev", "anything") == "critical"


def test_infer_cvss_score_critical():
    raw = "Vulnerability detail. CVSS Base Score: 9.8 (HIGH)"
    assert infer_severity_from_content("NVD", raw) == "critical"


def test_infer_cvss_score_high():
    assert infer_severity_from_content("NVD", "Score: 7.5") == "high"


def test_infer_cvss_score_medium():
    assert infer_severity_from_content("NVD", "cvss score: 5.2") == "medium"


def test_infer_no_pattern_returns_none():
    assert infer_severity_from_content("Reddit/r/netsec", "just a discussion") is None


# ──────────────────────────────────────────────
# TIMESTAMP -> UTC
# ──────────────────────────────────────────────

def test_to_utc_assumes_naive_is_utc():
    naive = datetime(2026, 5, 15, 10, 30)
    out = to_utc(naive)
    assert out.tzinfo == timezone.utc
    assert out.hour == 10


def test_to_stix_timestamp_z_suffix():
    s = to_stix_timestamp(datetime(2026, 5, 15, 0, 0, 0))
    assert s.endswith("Z")
    assert s == "2026-05-15T00:00:00Z"


# ──────────────────────────────────────────────
# LANGUAGE DETECTION (multilingual proof)
# ──────────────────────────────────────────────

def test_detect_english():
    assert detect_language("This is a security advisory about CVE-2026-1234.") == "en"


def test_detect_vietnamese():
    """Critical: brief yeu cau xu ly da ngon ngu, phai detect duoc tieng Viet."""
    vi = ("Lỗ hổng nghiêm trọng trong hệ thống xác thực, cho phép kẻ tấn công "
          "thực thi mã từ xa và chiếm quyền quản trị máy chủ web.")
    assert detect_language(vi) == "vi"


def test_detect_chinese():
    zh = "微软发布安全公告,修复了一个严重的远程代码执行漏洞,影响所有版本的服务器。"
    assert detect_language(zh) == "zh"


def test_detect_empty_falls_back_to_en():
    assert detect_language("") == "en"
    assert detect_language("   ") == "en"
