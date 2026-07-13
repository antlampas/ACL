# SPDX-License-Identifier: CC-BY-SA-4.0

"""Unit of work port for atomic ACL mutations."""

from __future__ import annotations

from contextlib import AbstractContextManager
from typing import Protocol


class UnitOfWork(Protocol):
    def transaction(self) -> AbstractContextManager[None]: ...
