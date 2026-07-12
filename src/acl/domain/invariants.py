# SPDX-License-Identifier: CC-BY-SA-4.0

"""Structural ACL entry invariants."""

from __future__ import annotations

from .decisions import JoinOp, Permission
from .entries import ACLEntry
from .errors import ACLValidationError
from .matching import entry_matches
from .operations import OperationSpec
from .profiles import Profile
from .subjects import SubjectRef, SubjectType


class ACLEntryInvariants:
    """Validate INV-1..INV-5, plus INV-2 with the operation spec."""

    def validate(self, entry: ACLEntry, operation: OperationSpec) -> None:
        self.validate_structural(entry)
        if entry.operation != operation.name:
            raise ACLValidationError(
                f"entry operation {entry.operation!r} does not match spec {operation.name!r}"
            )
        if (
            entry.permission == Permission.ALLOW
            and not operation.read_only
            and entry_matches(entry, SubjectRef.public(), Profile.anonymous())
        ):
            raise ACLValidationError(
                "INV-2: mutating ALLOW entries must not match the anonymous profile"
            )

    def validate_structural(self, entry: ACLEntry) -> None:
        if entry.level is None and entry.group is None:
            raise ACLValidationError("INV-1: ACL entries require level or group")
        if entry.level is not None:
            if not isinstance(entry.level, int) or entry.level < 0:
                raise ACLValidationError("INV-3: level must be an integer >= 0")
        if entry.group is not None and not entry.group:
            raise ACLValidationError("INV-3: group must be a non-empty string")
        if not isinstance(entry.profile_join, JoinOp) or not isinstance(entry.subject_join, JoinOp):
            raise ACLValidationError("INV-4: invalid join operation")
        if entry.subject.type == SubjectType.PUBLIC and entry.subject_join == JoinOp.OR:
            raise ACLValidationError("INV-5: PUBLIC entries cannot use subject_join=OR")
