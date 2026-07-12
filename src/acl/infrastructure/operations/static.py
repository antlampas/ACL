# SPDX-License-Identifier: CC-BY-SA-4.0

"""Static operation catalog."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from acl.domain import OperationSpec, OperationUnknownError


class StaticOperationCatalog:
    def __init__(self, operations: Iterable[OperationSpec] | Mapping[str, OperationSpec]) -> None:
        if isinstance(operations, Mapping):
            values = operations.values()
        else:
            values = operations
        self._operations = {operation.name: operation for operation in values}
        self.validate_bootstrap_safety()

    def get(self, operation: str) -> OperationSpec | None:
        return self._operations.get(operation.strip().upper())

    def require(self, operation: str) -> OperationSpec:
        spec = self.get(operation)
        if spec is None:
            raise OperationUnknownError(f"unknown ACL operation: {operation!r}")
        return spec

    def all(self) -> tuple[OperationSpec, ...]:
        return tuple(self._operations[name] for name in sorted(self._operations))

    def validate_bootstrap_safety(self) -> None:
        manage_acl = self._operations.get("MANAGE_ACL")
        if manage_acl is not None and (manage_acl.inheritable or not manage_acl.protected):
            raise ValueError("MANAGE_ACL must be non-inheritable and protected")
        manage_profiles = self._operations.get("MANAGE_PROFILES")
        if manage_profiles is not None and not manage_profiles.protected:
            raise ValueError("MANAGE_PROFILES must be protected")


def default_operation_catalog() -> StaticOperationCatalog:
    return StaticOperationCatalog(
        [
            OperationSpec("LIST", read_only=True, inheritable=True, protected=False),
            OperationSpec("VIEW", read_only=True, inheritable=True, protected=False),
            OperationSpec("CREATE", read_only=False, inheritable=False, protected=False),
            OperationSpec("EDIT", read_only=False, inheritable=True, protected=False),
            OperationSpec("DELETE", read_only=False, inheritable=True, protected=False),
            OperationSpec("UPLOAD", read_only=False, inheritable=True, protected=False),
            OperationSpec("ASSIGN", read_only=False, inheritable=True, protected=False),
            OperationSpec("MANAGE_ACL", read_only=False, inheritable=False, protected=True),
            OperationSpec("MANAGE_PROFILES", read_only=False, inheritable=False, protected=True),
            OperationSpec("MANAGE_IDENTITIES", read_only=False, inheritable=False, protected=True),
            OperationSpec("MANAGE_ACCOUNTS", read_only=False, inheritable=False, protected=True),
            OperationSpec("EXECUTE", read_only=False, inheritable=False, protected=True),
        ]
    )
