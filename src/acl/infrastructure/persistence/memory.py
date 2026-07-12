# SPDX-License-Identifier: CC-BY-SA-4.0

"""Deterministic in-memory ACL repository for tests and demos."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from contextlib import nullcontext
from threading import RLock

from acl.domain import ACLEntry, ACLEntryId, ResourceRef, SubjectRef


class NullUnitOfWork:
    def transaction(self):
        return nullcontext()


class InMemoryACLEntryRepository:
    def __init__(self, entries: Iterable[ACLEntry] = ()) -> None:
        self._entries: dict[str, ACLEntry] = {}
        self._lock = RLock()
        for entry in entries:
            self._entries[str(entry.id)] = entry

    def entries_for(self, resource: ResourceRef, operation: str) -> list[ACLEntry]:
        operation = operation.strip().upper()
        with self._lock:
            return self._sorted(
                entry
                for entry in self._entries.values()
                if entry.resource == resource and entry.operation == operation
            )

    def list_by_operation(self, operation: str, resource_type: str) -> list[ACLEntry]:
        operation = operation.strip().upper()
        resource_type = resource_type.strip().upper()
        with self._lock:
            return self._sorted(
                entry
                for entry in self._entries.values()
                if entry.operation == operation and entry.resource.type == resource_type
            )

    def list_by_resource(self, resource: ResourceRef) -> list[ACLEntry]:
        with self._lock:
            return self._sorted(entry for entry in self._entries.values() if entry.resource == resource)

    def get(self, entry_id: ACLEntryId) -> ACLEntry | None:
        with self._lock:
            return self._entries.get(str(entry_id))

    def save(self, entry: ACLEntry) -> None:
        with self._lock:
            self._entries[str(entry.id)] = entry

    def delete(self, entry_id: ACLEntryId) -> None:
        with self._lock:
            self._entries.pop(str(entry_id), None)

    def replace_entries(self, resource: ResourceRef, entries: Sequence[ACLEntry]) -> None:
        with self._lock:
            self._entries = {
                entry_id: entry
                for entry_id, entry in self._entries.items()
                if entry.resource != resource
            }
            for entry in entries:
                self._entries[str(entry.id)] = entry

    def delete_by_resource(self, resource: ResourceRef) -> None:
        with self._lock:
            self._entries = {
                entry_id: entry
                for entry_id, entry in self._entries.items()
                if entry.resource != resource
            }

    def delete_by_subject(self, subject: SubjectRef) -> None:
        with self._lock:
            self._entries = {
                entry_id: entry
                for entry_id, entry in self._entries.items()
                if entry.subject != subject
            }

    def is_empty(self) -> bool:
        with self._lock:
            return not self._entries

    def all_entries(self) -> list[ACLEntry]:
        with self._lock:
            return self._sorted(self._entries.values())

    @staticmethod
    def _sorted(entries: Iterable[ACLEntry]) -> list[ACLEntry]:
        return sorted(
            entries,
            key=lambda entry: (
                entry.resource.type,
                entry.resource.id,
                entry.operation,
                entry.subject.type.value,
                entry.subject.id or "",
                str(entry.id),
            ),
        )
