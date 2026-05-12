"""Database models for the Security Guardrail Auditor."""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.db import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    file_type = Column(String, nullable=False)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String, default="Low")
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    scanned_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "filename": self.filename,
            "file_type": self.file_type,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "total_findings": self.total_findings,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "scanned_at": self.scanned_at.isoformat(),
        }


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    rule_id = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    resource_type = Column(String, nullable=False)
    resource_name = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)

    scan = relationship("Scan", back_populates="findings")

    def to_dict(self):
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "description": self.description,
            "remediation": self.remediation,
        }
