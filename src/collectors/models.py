"""
models.py

Định nghĩa schema DB và các helper dùng chung cho tất cả collectors.

Exports:
    ThreatArticle  — ORM model lưu threat intel từ mọi nguồn
    Base           — SQLAlchemy declarative base (dùng khi tạo schema)
    engine         — SQLAlchemy engine (dùng khi tạo schema)
    get_session()  — trả về Session mới, gọi .close() sau khi dùng xong
    compute_hash() — SHA-256 hash của nội dung, dùng để dedup
"""
import hashlib
import sys
import os
from datetime import datetime

from sqlalchemy import (
    Column, Integer, String, Text, DateTime, create_engine
)
from sqlalchemy.orm import declarative_base, sessionmaker

# Thêm thư mục cha vào sys.path để tìm được config.py
# Cần thiết khi models.py và config.py nằm trong cùng folder collectors/
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config

# ──────────────────────────────────────────────
# ENGINE & SESSION
# ──────────────────────────────────────────────

engine = create_engine(
    config.DATABASE_URL,
    connect_args={"check_same_thread": False}
    if config.DATABASE_URL.startswith("sqlite")
    else {},
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

Base = declarative_base()


def get_session():
    """Trả về một Session mới. Gọi session.close() sau khi dùng xong."""
    return SessionLocal()


# ──────────────────────────────────────────────
# MODEL
# ──────────────────────────────────────────────

class ThreatArticle(Base):
    __tablename__ = "threat_articles"

    id           = Column(Integer, primary_key=True, autoincrement=True)

    # Nội dung
    title        = Column(String(500), nullable=False)
    source       = Column(String(100), nullable=False)
    url          = Column(Text, nullable=False)
    raw_content  = Column(Text, nullable=False)

    # Dedup — SHA-256 của raw_content
    content_hash = Column(String(64), unique=True, nullable=False, index=True)

    # Metadata
    severity     = Column(String(20), nullable=True)
    published_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_at   = Column(DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<ThreatArticle id={self.id} source={self.source!r} title={self.title[:40]!r}>"


# ──────────────────────────────────────────────
# HELPER
# ──────────────────────────────────────────────

def compute_hash(content: str) -> str:
    """Trả về SHA-256 hex digest của chuỗi content (UTF-8)."""
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()