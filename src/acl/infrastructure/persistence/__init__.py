# SPDX-License-Identifier: CC-BY-SA-4.0

"""Persistence adapters."""

from .file_json import JsonFileACLEntryRepository
from .memory import InMemoryACLEntryRepository, NullUnitOfWork

__all__ = [
    "InMemoryACLEntryRepository",
    "JsonFileACLEntryRepository",
    "NullUnitOfWork",
]
