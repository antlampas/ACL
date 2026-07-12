# SPDX-License-Identifier: CC-BY-SA-4.0

"""Authoritative authorization profile resolved for a request subject."""

from __future__ import annotations

from dataclasses import dataclass

from .identifiers import ANON_SENTINEL, PUBLIC_GROUP


@dataclass(frozen=True, slots=True)
class Profile:
    level: int
    groups: frozenset[str]
    version: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.level, int):
            raise ValueError("profile level must be an integer")
        if self.level < 0:
            raise ValueError("profile level must be >= 0")
        if self.level > ANON_SENTINEL:
            raise ValueError("profile level cannot exceed ANON_SENTINEL")

        normalized = frozenset(str(group).strip() for group in self.groups if str(group).strip())
        if self.level == ANON_SENTINEL and normalized - {PUBLIC_GROUP}:
            raise ValueError("anonymous profile cannot belong to non-public groups")

        object.__setattr__(self, "groups", normalized | {PUBLIC_GROUP})

    @staticmethod
    def anonymous() -> "Profile":
        return Profile(level=ANON_SENTINEL, groups=frozenset({PUBLIC_GROUP}))

    def stored_groups(self) -> frozenset[str]:
        return self.groups - {PUBLIC_GROUP}
