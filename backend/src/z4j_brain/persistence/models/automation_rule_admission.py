"""Exact rolling-window admissions for automation-rule actions.

One ordinary row is one normal-mode rule firing admitted by the circuit
breaker. A migration may use one weighted row to conservatively carry forward
legacy aggregate state whose individual timestamps never existed. The rule
row is the concurrency arbiter; callers lock it before pruning, summing, and
inserting this bounded child history.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from z4j_brain.persistence.base import Base
from z4j_brain.persistence.models._mixins import PKMixin


class AutomationRuleAdmission(PKMixin, Base):
    """One breaker admission in the current rule-configuration epoch."""

    __tablename__ = "automation_rule_admissions"

    rule_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("automation_rules.id", ondelete="CASCADE"),
        nullable=False,
    )
    admitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    weight: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default="1",
    )

    __table_args__ = (
        CheckConstraint(
            "weight > 0",
            name="ck_automation_rule_admissions_positive_weight",
        ),
        Index(
            "ix_automation_rule_admissions_rule_time",
            "rule_id",
            "admitted_at",
        ),
    )


__all__ = ["AutomationRuleAdmission"]
