# SPDX-License-Identifier: CC-BY-SA-4.0

"""Resource references for concrete resources, type roots and global scope."""

from __future__ import annotations

from dataclasses import dataclass

from .identifiers import SYSTEM_ID, SYSTEM_TYPE, TYPE_ROOT_ID


@dataclass(frozen=True, slots=True, order=True)
class ResourceRef:
    type: str
    id: str

    def __post_init__(self) -> None:
        resource_type = str(self.type).strip().upper()
        resource_id = str(self.id).strip()
        if not resource_type:
            raise ValueError("resource type must be non-empty")
        if not resource_id:
            raise ValueError("resource id must be non-empty")
        object.__setattr__(self, "type", resource_type)
        object.__setattr__(self, "id", resource_id)

    @staticmethod
    def system() -> "ResourceRef":
        return ResourceRef(SYSTEM_TYPE, SYSTEM_ID)

    @staticmethod
    def type_root(resource_type: str) -> "ResourceRef":
        return ResourceRef(resource_type, TYPE_ROOT_ID)

    @staticmethod
    def concrete(resource_type: str, resource_id: str) -> "ResourceRef":
        return ResourceRef(resource_type, resource_id)

    @property
    def is_system(self) -> bool:
        return self.type == SYSTEM_TYPE and self.id == SYSTEM_ID

    @property
    def is_type_root(self) -> bool:
        return self.id == TYPE_ROOT_ID

    @property
    def is_concrete(self) -> bool:
        return not self.is_system and not self.is_type_root
