"""
schema.py — ORM cho output của Layer 2 (và sau đó Layer 3).

Hai bảng:
    stix_objects        — mọi SDO/SCO (report, identity, indicator, malware, …)
                          được lưu dưới dạng JSON đầy đủ + các cột scalar
                          để Layer 6 filter/search nhanh.
    stix_relationships  — SROs (relationship), tách riêng để query đồ thị
                          (actor uses malware, indicator indicates malware…).

Dùng `declarative_base()` riêng, KHÔNG đụng tới Base của collectors —
khi gọi `Base.metadata.create_all(engine)` chỉ tạo 2 bảng này,
không ảnh hưởng tới `threat_articles` của Layer 1.
"""
from sqlalchemy import Column, String, Text, DateTime, Index
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class StixObject(Base):
    """Một row = một STIX SDO (vd: report--xxxx, identity--yyyy, indicator--zzzz)."""

    __tablename__ = "stix_objects"

    # STIX id (vd: "report--ae73a645-...") — duy nhất cross-source nhờ UUIDv5
    id          = Column(String(120), primary_key=True)

    # STIX type (report, identity, indicator, malware, vulnerability, …)
    type        = Column(String(40), nullable=False, index=True)

    # Denormalized fields cho Layer 6 dashboard filter (không bắt buộc có)
    name        = Column(Text,        nullable=True)
    source      = Column(String(100), nullable=True, index=True)
    severity    = Column(String(20),  nullable=True, index=True)
    lang        = Column(String(10),  nullable=True)

    # Timestamps (UTC). published = report.published; valid_from = indicator.valid_from
    published   = Column(DateTime, nullable=True, index=True)
    valid_from  = Column(DateTime, nullable=True)
    created     = Column(DateTime, nullable=False)
    modified    = Column(DateTime, nullable=False)

    # Truy ngược về row gốc trong threat_articles (chỉ có với report)
    raw_article_id = Column(String(20), nullable=True, index=True)

    # Full STIX JSON (TEXT trên SQLite, sẽ là JSONB khi migrate sang Postgres)
    doc         = Column(Text, nullable=False)

    def __repr__(self):
        return f"<StixObject {self.id} source={self.source!r}>"


class StixRelationship(Base):
    """Một row = một SRO (STIX `relationship` object)."""

    __tablename__ = "stix_relationships"

    id                = Column(String(120), primary_key=True)
    source_ref        = Column(String(120), nullable=False, index=True)
    target_ref        = Column(String(120), nullable=False, index=True)
    relationship_type = Column(String(50),  nullable=False, index=True)
    created           = Column(DateTime, nullable=False)
    modified          = Column(DateTime, nullable=False)
    doc               = Column(Text, nullable=False)

    __table_args__ = (
        Index("ix_stix_rel_src_tgt", "source_ref", "target_ref"),
    )

    def __repr__(self):
        return (f"<StixRelationship {self.relationship_type}: "
                f"{self.source_ref} -> {self.target_ref}>")
