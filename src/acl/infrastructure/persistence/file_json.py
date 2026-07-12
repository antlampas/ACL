# SPDX-License-Identifier: CC-BY-SA-4.0

"""Atomic single-file JSON repository for prototypes and single-writer use."""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from pathlib import Path

from acl.domain import ACLEntry, ACLEntryId, ResourceRef, SubjectRef

from .memory import InMemoryACLEntryRepository
from .serialization import entry_from_dict, entry_to_dict


class JsonFileACLEntryRepository(InMemoryACLEntryRepository):
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        entries = self._load_entries()
        super().__init__(entries)

    def save(self, entry: ACLEntry) -> None:
        super().save(entry)
        self._flush()

    def delete(self, entry_id: ACLEntryId) -> None:
        super().delete(entry_id)
        self._flush()

    def replace_entries(self, resource: ResourceRef, entries: Sequence[ACLEntry]) -> None:
        super().replace_entries(resource, entries)
        self._flush()

    def delete_by_resource(self, resource: ResourceRef) -> None:
        super().delete_by_resource(resource)
        self._flush()

    def delete_by_subject(self, subject: SubjectRef) -> None:
        super().delete_by_subject(subject)
        self._flush()

    def _load_entries(self) -> list[ACLEntry]:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)
        return [entry_from_dict(item) for item in payload.get("entries", [])]

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(f"{self.path.suffix}.tmp")
        payload = {"entries": [entry_to_dict(entry) for entry in self.all_entries()]}
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, self.path)
