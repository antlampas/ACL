# SPDX-License-Identifier: CC-BY-SA-4.0

"""ACL entry value object."""

from __future__ import annotations

from dataclasses import dataclass

from .decisions import JoinOp, Permission
from .identifiers import ACLEntryId
from .resources import ResourceRef
from .subjects import SubjectRef


@dataclass(frozen=True, slots=True)
class ACLEntry:
    id: ACLEntryId
    subject: SubjectRef
    resource: ResourceRef
    operation: str
    permission: Permission
    level: int | None = None
    group: str | None = None
    profile_join: JoinOp = JoinOp.OR
    subject_join: JoinOp = JoinOp.AND

    def __post_init__(self) -> None:
        entry_id = str(self.id).strip()
        operation = str(self.operation).strip().upper()
        group = None if self.group is None else str(self.group).strip()
        if not entry_id:
            raise ValueError("entry id must be non-empty")
        if not operation:
            raise ValueError("entry operation must be non-empty")
        object.__setattr__(self, "id", ACLEntryId(entry_id))
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "permission", Permission(self.permission))
        object.__setattr__(self, "profile_join", JoinOp(self.profile_join))
        object.__setattr__(self, "subject_join", JoinOp(self.subject_join))
        object.__setattr__(self, "group", group)
