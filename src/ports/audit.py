# SPDX-License-Identifier: CC-BY-SA-4.0

"""Audit event port."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol


@dataclass(frozen=True, slots=True)
class AuditEvent:
    type: str
    actor: str | None = None
    resource: str | None = None
    entry_id: str | None = None
    detail: Mapping[str, str] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class AuditLogger(Protocol):
    def append(self, event: AuditEvent) -> None: ...
