# SPDX-License-Identifier: CC-BY-SA-4.0

"""Serialization helpers for persistence adapters."""

from __future__ import annotations

from acl.domain import ACLEntry, ACLEntryId, JoinOp, Permission, ResourceRef, SubjectRef, SubjectType


def entry_to_dict(entry: ACLEntry) -> dict[str, object]:
    return {
        "id": str(entry.id),
        "subject_type": entry.subject.type.value,
        "subject_id": entry.subject.id,
        "resource_type": entry.resource.type,
        "resource_id": entry.resource.id,
        "operation": entry.operation,
        "permission": entry.permission.value,
        "level": entry.level,
        "group_id": entry.group,
        "profile_join": entry.profile_join.value,
        "subject_join": entry.subject_join.value,
    }


def entry_from_dict(data: dict[str, object]) -> ACLEntry:
    return ACLEntry(
        id=ACLEntryId(str(data["id"])),
        subject=SubjectRef(
            SubjectType(str(data["subject_type"])),
            None if data.get("subject_id") is None else str(data["subject_id"]),
        ),
        resource=ResourceRef(str(data["resource_type"]), str(data["resource_id"])),
        operation=str(data["operation"]),
        permission=Permission(str(data["permission"])),
        level=None if data.get("level") is None else int(data["level"]),
        group=None if data.get("group_id") is None else str(data["group_id"]),
        profile_join=JoinOp(str(data["profile_join"])),
        subject_join=JoinOp(str(data["subject_join"])),
    )
