# SPDX-License-Identifier: CC-BY-SA-4.0

"""Operation catalog port."""

from __future__ import annotations

from typing import Protocol

from acl.domain import OperationSpec


class OperationCatalog(Protocol):
    def get(self, operation: str) -> OperationSpec | None: ...
    def require(self, operation: str) -> OperationSpec: ...
