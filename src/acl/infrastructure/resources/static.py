# SPDX-License-Identifier: CC-BY-SA-4.0

"""Static resource hierarchy for tests and simple domains."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from acl.domain import ResourceRef


class StaticResourceHierarchyProvider:
    def __init__(
        self,
        parents: Mapping[ResourceRef, Sequence[ResourceRef]] | None = None,
        include_type_roots: bool = True,
    ) -> None:
        self._parents = {resource: tuple(values) for resource, values in (parents or {}).items()}
        self._include_type_roots = include_type_roots

    def parents_of(self, resource: ResourceRef) -> list[ResourceRef]:
        parents = list(self._parents.get(resource, ()))
        if self._include_type_roots and resource.is_concrete:
            root = ResourceRef.type_root(resource.type)
            if root not in parents:
                parents.append(root)
        return [parent for parent in parents if parent != resource]
