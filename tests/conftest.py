# SPDX-License-Identifier: CC-BY-SA-4.0

from __future__ import annotations

from collections.abc import Mapping, Sequence

import pytest

from application import AuthorizationPolicy
from domain import ACLEntry, ACLEntryId, Permission, Profile, ResourceRef, SubjectRef
from infrastructure.operations import default_operation_catalog
from infrastructure.persistence import InMemoryACLEntryRepository
from infrastructure.profiles import InMemoryProfileProvider
from infrastructure.resources import StaticResourceHierarchyProvider


@pytest.fixture
def catalog():
    return default_operation_catalog()


def acl_entry(
    entry_id: str,
    subject: SubjectRef,
    resource: ResourceRef,
    operation: str,
    permission: Permission = Permission.ALLOW,
    level: int | None = None,
    group: str | None = None,
) -> ACLEntry:
    return ACLEntry(
        id=ACLEntryId(entry_id),
        subject=subject,
        resource=resource,
        operation=operation,
        permission=permission,
        level=level,
        group=group,
    )


def make_policy(
    entries: Sequence[ACLEntry] = (),
    profiles: Mapping[SubjectRef, Profile] | None = None,
    parents: Mapping[ResourceRef, Sequence[ResourceRef]] | None = None,
) -> tuple[AuthorizationPolicy, InMemoryACLEntryRepository, InMemoryProfileProvider]:
    repo = InMemoryACLEntryRepository(entries)
    profile_provider = InMemoryProfileProvider(dict(profiles or {}))
    hierarchy = StaticResourceHierarchyProvider(parents)
    policy = AuthorizationPolicy(repo, profile_provider, hierarchy, default_operation_catalog())
    return policy, repo, profile_provider
