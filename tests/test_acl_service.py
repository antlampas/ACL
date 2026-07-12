# SPDX-License-Identifier: CC-BY-SA-4.0

from __future__ import annotations

import pytest

from acl.application import ACLEntryInput, ACLService, AuthorizationPolicy, SeedRule, SeedingPolicy
from acl.domain import (
    ACLEntryId,
    ACLValidationError,
    GrantConstraintError,
    Permission,
    Profile,
    ResourceRef,
    SubjectRef,
)
from acl.infrastructure.operations import default_operation_catalog
from acl.infrastructure.persistence import InMemoryACLEntryRepository
from acl.infrastructure.profiles import InMemoryProfileProvider
from acl.infrastructure.resources import StaticResourceHierarchyProvider
from acl.ports import RequestIdentity
from tests.conftest import acl_entry


def make_service():
    admin = SubjectRef.user("admin")
    manager = SubjectRef.user("manager")
    doc = ResourceRef("DOC", "1")
    repo = InMemoryACLEntryRepository(
        [
            acl_entry("global-admin", SubjectRef.public(), ResourceRef.system(), "MANAGE_ACL", level=0),
            acl_entry("local-manager", manager, doc, "MANAGE_ACL", level=2**31 - 1),
        ]
    )
    profiles = InMemoryProfileProvider(
        {
            admin: Profile(0, frozenset({"admins"})),
            manager: Profile(50, frozenset()),
        }
    )
    catalog = default_operation_catalog()
    policy = AuthorizationPolicy(repo, profiles, StaticResourceHierarchyProvider(), catalog)
    service = ACLService(repo, policy, profiles, catalog, id_factory=lambda: "new-id")
    return service, repo, admin, manager, doc


def test_create_entry_requires_manage_acl() -> None:
    service, _, _, _, doc = make_service()
    stranger = RequestIdentity(SubjectRef.user("stranger"), authenticated=True)

    with pytest.raises(GrantConstraintError, match="MANAGE_ACL"):
        service.create_entry(
            stranger,
            ACLEntryInput(
                subject=SubjectRef.user("alice"),
                resource=doc,
                operation="VIEW",
                permission=Permission.ALLOW,
            ),
        )


def test_local_manager_can_grant_unprotected_operation_with_default_subject_level() -> None:
    service, repo, _, manager, doc = make_service()

    dto = service.create_entry(
        RequestIdentity(manager, authenticated=True),
        ACLEntryInput(
            subject=SubjectRef.user("alice"),
            resource=doc,
            operation="VIEW",
            permission=Permission.ALLOW,
        ),
    )

    saved = repo.get(dto.id)
    assert saved is not None
    assert saved.level == 2**31 - 1


def test_local_manager_cannot_grant_protected_operation() -> None:
    service, _, _, manager, doc = make_service()

    with pytest.raises(GrantConstraintError, match="protected operation"):
        service.create_entry(
            RequestIdentity(manager, authenticated=True),
            ACLEntryInput(
                subject=SubjectRef.user("alice"),
                resource=doc,
                operation="MANAGE_ACL",
                permission=Permission.ALLOW,
            ),
        )


def test_type_root_management_requires_global_manage_acl() -> None:
    service, _, _, manager, _ = make_service()

    with pytest.raises(GrantConstraintError, match="global MANAGE_ACL"):
        service.create_entry(
            RequestIdentity(manager, authenticated=True),
            ACLEntryInput(
                subject=SubjectRef.user("alice"),
                resource=ResourceRef.type_root("DOC"),
                operation="VIEW",
                permission=Permission.ALLOW,
            ),
        )


def test_replace_entries_validates_before_mutating_repository() -> None:
    service, repo, admin, _, doc = make_service()
    before = repo.list_by_resource(doc)

    with pytest.raises(ACLValidationError):
        service.replace_entries(
            RequestIdentity(admin, authenticated=True),
            doc,
            [
                ACLEntryInput(
                    id=ACLEntryId("valid"),
                    subject=SubjectRef.user("alice"),
                    resource=doc,
                    operation="VIEW",
                    permission=Permission.ALLOW,
                ),
                ACLEntryInput(
                    id=ACLEntryId("invalid"),
                    subject=SubjectRef.public(),
                    resource=doc,
                    operation="EDIT",
                    permission=Permission.ALLOW,
                ),
            ],
        )

    assert repo.list_by_resource(doc) == before


def test_seeding_creates_revocable_creator_entries() -> None:
    creator = SubjectRef.user("creator")
    resource = ResourceRef("DOC", "created")
    repo = InMemoryACLEntryRepository()
    profiles = InMemoryProfileProvider({creator: Profile(10, frozenset())})
    catalog = default_operation_catalog()
    policy = AuthorizationPolicy(repo, profiles, StaticResourceHierarchyProvider(), catalog)
    seeding = SeedingPolicy(
        enabled=True,
        rules={"DOC": SeedRule("DOC", frozenset({"VIEW", "EDIT"}))},
    )
    service = ACLService(
        repo,
        policy,
        profiles,
        catalog,
        seeding_policy=seeding,
        id_factory=iter(["seed-view", "seed-edit"]).__next__,
    )

    service.on_resource_created(resource, creator, "DOC")

    entries = repo.list_by_resource(resource)
    assert {entry.operation for entry in entries} == {"VIEW", "EDIT"}
    assert all(entry.subject == creator for entry in entries)
