from datetime import date, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    false,
    func,
    true,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from apps.server.db import Base

DOCUMENT = JSON().with_variant(JSONB(), "postgresql")
IDENTITY = BigInteger().with_variant(Integer(), "sqlite")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PUBLISHED','REJECTED','RESERVED','UNKNOWN')",
            name="ck_vulnerability_status",
        ),
        CheckConstraint("cvss IS NULL OR (cvss >= 0 AND cvss <= 10)", name="ck_vulnerability_cvss"),
        Index("ix_vulnerabilities_status_modified", "status", "modified_at"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    title: Mapped[str] = mapped_column(Text, default="", nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cvss: Mapped[float | None] = mapped_column(Float)
    cvss_version: Mapped[str | None] = mapped_column(String(8))
    cvss_vector: Mapped[str | None] = mapped_column(Text)
    cvss_source: Mapped[str | None] = mapped_column(String(32))
    cvss_metrics: Mapped[list] = mapped_column(DOCUMENT, default=list, nullable=False)
    severity: Mapped[str | None] = mapped_column(String(16))
    cwes: Mapped[list] = mapped_column(DOCUMENT, default=list, nullable=False)
    ssvc: Mapped[dict | None] = mapped_column(DOCUMENT)
    adp_kev_flag: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=false(), nullable=False
    )
    cisa_adp: Mapped[dict | None] = mapped_column(DOCUMENT)
    source_url: Mapped[str | None] = mapped_column(Text)
    record_hash: Mapped[str | None] = mapped_column(String(64))
    raw_record: Mapped[dict | None] = mapped_column(DOCUMENT)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class VulnerabilityAlias(Base):
    __tablename__ = "vulnerability_aliases"
    vulnerability_id: Mapped[str] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), primary_key=True
    )
    alias: Mapped[str] = mapped_column(String(128), primary_key=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    __table_args__ = (Index("ix_vulnerability_aliases_alias", "alias"),)


class AffectedPackage(Base):
    __tablename__ = "affected_packages"
    __table_args__ = (
        UniqueConstraint(
            "vulnerability_id", "source", "entry_hash", name="uq_affected_source_entry"
        ),
        CheckConstraint(
            "status IN ('fixed','unfixed','wont_fix','unknown')", name="ck_affected_status"
        ),
        Index("ix_affected_lookup", "ecosystem", "package_name"),
    )
    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[str] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False
    )
    ecosystem: Mapped[str] = mapped_column(String(128), nullable=False)
    distro: Mapped[str | None] = mapped_column(String(32))
    release: Mapped[str | None] = mapped_column(String(64))
    package_name: Mapped[str] = mapped_column(String(256), nullable=False)
    source_package: Mapped[str | None] = mapped_column(String(256))
    ranges: Mapped[list] = mapped_column(DOCUMENT, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    fixed_version: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    source_url: Mapped[str] = mapped_column(Text, nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class KEVEntry(Base):
    __tablename__ = "kev_entries"
    vulnerability_id: Mapped[str] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), primary_key=True
    )
    date_added: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    due_date: Mapped[date | None] = mapped_column(Date)
    vendor: Mapped[str] = mapped_column(Text, nullable=False)
    product: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    required_action: Mapped[str] = mapped_column(Text, nullable=False)
    ransomware: Mapped[str] = mapped_column(String(32), nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False)
    catalog_version: Mapped[str] = mapped_column(String(64), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, server_default=true(), nullable=False
    )
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class EPSSScore(Base):
    __tablename__ = "epss_scores"
    __table_args__ = (
        CheckConstraint("epss >= 0 AND epss <= 1", name="ck_epss_probability"),
        CheckConstraint("percentile >= 0 AND percentile <= 1", name="ck_epss_percentile"),
    )
    vulnerability_id: Mapped[str] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), primary_key=True
    )
    score_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    epss: Mapped[Decimal] = mapped_column(Numeric(10, 9), nullable=False)
    percentile: Mapped[Decimal] = mapped_column(Numeric(10, 9), nullable=False)
    model_version: Mapped[str] = mapped_column(String(64), nullable=False)


class VulnerabilityEvent(Base):
    __tablename__ = "vulnerability_events"
    __table_args__ = (
        Index("ix_events_time_priority", "happened_at", "priority"),
        Index("ix_events_public_time", "is_baseline", "happened_at"),
    )
    id: Mapped[int] = mapped_column(IDENTITY, primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[str] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    dedup_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    happened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    priority: Mapped[str] = mapped_column(String(8), nullable=False)
    is_baseline: Mapped[bool] = mapped_column(
        Boolean, default=True, server_default=true(), nullable=False
    )
    payload: Mapped[dict[str, Any]] = mapped_column(DOCUMENT, nullable=False)


class IngestionState(Base):
    __tablename__ = "ingestion_state"
    source: Mapped[str] = mapped_column(String(64), primary_key=True)
    source_revision: Mapped[str | None] = mapped_column(Text)
    cursor: Mapped[dict] = mapped_column(DOCUMENT, default=dict, nullable=False)
    records_processed: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    completed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    has_completed: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=false(), nullable=False
    )
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_error: Mapped[str | None] = mapped_column(Text)
