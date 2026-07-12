# SPDX-License-Identifier: CC-BY-SA-4.0

"""Audit loggers based on stdlib logging or in-memory collection."""

from __future__ import annotations

import logging
from threading import RLock

from acl.ports import AuditEvent


class NoopAuditLogger:
    def append(self, event: AuditEvent) -> None:
        return None


class InMemoryAuditLogger:
    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._lock = RLock()

    def append(self, event: AuditEvent) -> None:
        with self._lock:
            self._events.append(event)

    def events(self) -> tuple[AuditEvent, ...]:
        with self._lock:
            return tuple(self._events)


class LoggingAuditLogger:
    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger("acl.audit")

    def append(self, event: AuditEvent) -> None:
        self._logger.info(
            "acl.audit",
            extra={
                "acl_event_type": event.type,
                "acl_actor": event.actor,
                "acl_resource": event.resource,
                "acl_entry_id": event.entry_id,
                "acl_detail": dict(event.detail),
                "acl_created_at": event.created_at.isoformat(),
            },
        )
