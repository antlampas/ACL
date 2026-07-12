# SPDX-License-Identifier: CC-BY-SA-4.0

"""Default dependency assembly for tests, demos and small applications."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from acl.application import ACLService, AuthorizationPolicy, AuthorizationService, BootstrapService, SeedingPolicy
from acl.bootstrap.container import ACLContainer
from acl.domain import Profile, ResourceRef, SubjectRef
from acl.infrastructure.audit import InMemoryAuditLogger
from acl.infrastructure.operations import StaticOperationCatalog, default_operation_catalog
from acl.infrastructure.persistence import InMemoryACLEntryRepository, NullUnitOfWork
from acl.infrastructure.profiles import InMemoryProfileProvider
from acl.infrastructure.resources import StaticResourceHierarchyProvider


def create_acl_container(
    profiles: Mapping[SubjectRef, Profile] | None = None,
    parents: Mapping[ResourceRef, Sequence[ResourceRef]] | None = None,
    operations: StaticOperationCatalog | None = None,
    seeding_policy: SeedingPolicy | None = None,
) -> ACLContainer:
    entries = InMemoryACLEntryRepository()
    profile_provider = InMemoryProfileProvider(dict(profiles or {}))
    hierarchy = StaticResourceHierarchyProvider(parents)
    operation_catalog = operations or default_operation_catalog()
    audit = InMemoryAuditLogger()
    policy = AuthorizationPolicy(entries, profile_provider, hierarchy, operation_catalog)
    uow = NullUnitOfWork()
    authorization = AuthorizationService(policy, audit=audit)
    acl = ACLService(
        entries=entries,
        policy=policy,
        profiles=profile_provider,
        operations=operation_catalog,
        uow=uow,
        audit=audit,
        seeding_policy=seeding_policy,
    )
    bootstrap = BootstrapService(
        entries=entries,
        operations=operation_catalog,
        profile_writer=profile_provider,
        uow=uow,
        audit=audit,
    )
    return ACLContainer(
        entries=entries,
        profiles=profile_provider,
        hierarchy=hierarchy,
        operations=operation_catalog,
        audit=audit,
        policy=policy,
        authorization=authorization,
        acl=acl,
        bootstrap=bootstrap,
    )
