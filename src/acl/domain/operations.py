# SPDX-License-Identifier: CC-BY-SA-4.0

"""Operation specifications from the ACL operation catalog."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class OperationSpec:
    name: str
    read_only: bool
    inheritable: bool = True
    protected: bool = False

    def __post_init__(self) -> None:
        name = str(self.name).strip().upper()
        if not name:
            raise ValueError("operation name must be non-empty")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "read_only", bool(self.read_only))
        object.__setattr__(self, "inheritable", bool(self.inheritable))
        object.__setattr__(self, "protected", bool(self.protected))
