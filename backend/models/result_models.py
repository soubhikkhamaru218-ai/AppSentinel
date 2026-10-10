"""
AppSentinel // SQLAlchemy ORM Models
Stores scan history, evidence items, and correlation results.
"""

import json
from datetime import datetime, timezone

from sqlalchemy import (
    Column, Integer, String, Float, Text, DateTime, ForeignKey, Boolean,
)
from sqlalchemy.orm import relationship

from backend.models.database import Base


class ScanRecord(Base):
    """
    Master record for each scan submission.
    One scan can have multiple evidence items and triggered rules.
    """
    __tablename__ = "scan_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(30), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # What the user submitted
    scan_mode = Column(String(20), nullable=False)  # "message", "url", "apk", "full"
    input_message = Column(Text, default="")
    input_identity = Column(String(255), default="")
    input_url = Column(String(2048), default="")
    input_apk_filename = Column(String(255), default="")
    input_apk_hash = Column(String(64), default="")

    # Verdict output
    verdict = Column(String(30), nullable=False)  # HIGH_RISK, SUSPICIOUS, LOW_CONCERN, INSUFFICIENT_EVIDENCE
    confidence = Column(Float, default=0.0)
    vector_count = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    triggered_rules = Column(String(100), default="")  # Comma-separated: "R1,R2,R4"

    # AI-generated explanation
    explanation = Column(Text, default="")
    actions_json = Column(Text, default="[]")  # JSON array of action strings

    # Relationships
    evidence_items = relationship("EvidenceItem", back_populates="scan", cascade="all, delete-orphan")

    def set_triggered_rules(self, rules: list[str]):
        self.triggered_rules = ",".join(rules)

    def get_triggered_rules(self) -> list[str]:
        if not self.triggered_rules:
            return []
        return [r.strip() for r in self.triggered_rules.split(",") if r.strip()]

    def set_actions(self, actions: list[str]):
        self.actions_json = json.dumps(actions)

    def get_actions(self) -> list[str]:
        try:
            return json.loads(self.actions_json)
        except (json.JSONDecodeError, TypeError):
            return []

    def __repr__(self):
        return f"<ScanRecord {self.scan_id} verdict={self.verdict}>"


class EvidenceItem(Base):
    """
    Individual evidence node in the correlation chain.
    Each scan produces 0..N evidence items.
    """
    __tablename__ = "evidence_items"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scan_records.id"), nullable=False)

    node_label = Column(String(100), nullable=False)  # e.g. "APK Installation Coercion"
    description = Column(Text, nullable=False)
    severity = Column(String(20), default="info")  # "info", "warning", "critical"
    rule_ref = Column(String(10), default="")  # e.g. "R1"
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationship back to parent scan
    scan = relationship("ScanRecord", back_populates="evidence_items")

    def __repr__(self):
        return f"<EvidenceItem [{self.rule_ref}] {self.node_label}>"
