# SPDX-License-Identifier: CC-BY-SA-4.0

"""Container object returned by the default composition root."""

from __future__ import annotations

from dataclasses import dataclass

from application import ACLService, AuthorizationPolicy, AuthorizationService, BootstrapService
from infrastructure.audit import InMemoryAuditLogger
from infrastructure.operations import StaticOperationCatalog
from infrastructure.persistence import InMemoryACLEntryRepository
from infrastructure.profiles import InMemoryProfileProvider
from infrastructure.resources import StaticResourceHierarchyProvider


@dataclass(slots=True)
class ACLContainer:
    entries: InMemoryACLEntryRepository
    profiles: InMemoryProfileProvider
    hierarchy: StaticResourceHierarchyProvider
    operations: StaticOperationCatalog
    audit: InMemoryAuditLogger
    policy: AuthorizationPolicy
    authorization: AuthorizationService
    acl: ACLService
    bootstrap: BootstrapService
