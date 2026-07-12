# SPDX-License-Identifier: CC-BY-SA-4.0

"""Resource hierarchy provider port."""

from __future__ import annotations

from typing import Protocol

from acl.domain import ResourceRef


class ResourceHierarchyProvider(Protocol):
    def parents_of(self, resource: ResourceRef) -> list[ResourceRef]: ...
