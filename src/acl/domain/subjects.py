# SPDX-License-Identifier: CC-BY-SA-4.0

"""Subject references used by ACL entries and requests."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class SubjectType(StrEnum):
    USER = "USER"
    PUBLIC = "PUBLIC"
    SERVICE = "SERVICE"


@dataclass(frozen=True, slots=True)
class SubjectRef:
    type: SubjectType
    id: str | None = None

    def __post_init__(self) -> None:
        subject_type = SubjectType(self.type)
        subject_id = None if self.id is None else str(self.id).strip()
        if subject_type is SubjectType.PUBLIC:
            if subject_id not in (None, ""):
                raise ValueError("PUBLIC subjects must not have an id")
            subject_id = None
        elif not subject_id:
            raise ValueError(f"{subject_type.value} subjects require a non-empty id")
        object.__setattr__(self, "type", subject_type)
        object.__setattr__(self, "id", subject_id)

    @staticmethod
    def public() -> "SubjectRef":
        return SubjectRef(SubjectType.PUBLIC, None)

    @staticmethod
    def user(subject_id: str) -> "SubjectRef":
        return SubjectRef(SubjectType.USER, subject_id)

    @staticmethod
    def service(subject_id: str) -> "SubjectRef":
        return SubjectRef(SubjectType.SERVICE, subject_id)
