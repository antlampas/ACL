# SPDX-License-Identifier: CC-BY-SA-4.0

from __future__ import annotations

import pytest

from acl.adapters.identity import ContextIdentityResolver
from acl.adapters.requests import InvocationContext, MappingRequestNormalizer, RequestMappingRule
from acl.application import BootstrapACLConfig, BootstrapService, InitialAdminInput
from acl.domain import ACLEntryId, Permission, Profile, ResourceMappingError, ResourceRef, SubjectRef
from acl.infrastructure.operations import default_operation_catalog
from acl.infrastructure.persistence import InMemoryACLEntryRepository
from acl.infrastructure.profiles import InMemoryProfileProvider
from tests.conftest import acl_entry


def test_bootstrap_creates_initial_entries_and_initial_admin_profile() -> None:
    repo = InMemoryACLEntryRepository()
    profiles = InMemoryProfileProvider()
    service = BootstrapService(repo, default_operation_catalog(), profile_writer=profiles)
    admin = SubjectRef.user("admin")

    service.ensure_bootstrap_entries(BootstrapACLConfig(resource_roots=frozenset({"DOC"})))
    service.create_initial_admin(InitialAdminInput(admin))

    assert not repo.is_empty()
    assert profiles.profile_of(admin).level == 0
    assert "admins" in profiles.profile_of(admin).groups


def test_bootstrap_does_not_overwrite_existing_entries() -> None:
    existing = acl_entry(
        "existing",
        SubjectRef.public(),
        ResourceRef.type_root("DOC"),
        "VIEW",
        Permission.ALLOW,
        group="public",
    )
    repo = InMemoryACLEntryRepository([existing])
    service = BootstrapService(repo, default_operation_catalog())

    service.ensure_bootstrap_entries(BootstrapACLConfig(resource_roots=frozenset({"DOC"})))

    assert repo.all_entries() == [existing]


def test_mapping_request_normalizer_maps_concrete_resource() -> None:
    normalizer = MappingRequestNormalizer(
        [
            RequestMappingRule(
                selector="doc.view",
                operation="VIEW",
                resource_type="DOC",
                resource_id_source="doc_id",
            )
        ]
    )
    identity = ContextIdentityResolver().resolve({"subject": SubjectRef.user("alice")})

    request = normalizer.authorization_request(
        InvocationContext("doc.view", resource_ids={"doc_id": "123"}),
        identity,
    )

    assert request.operation == "VIEW"
    assert request.resource == ResourceRef("DOC", "123")


def test_mapping_request_normalizer_fails_closed_for_unmapped_selector() -> None:
    normalizer = MappingRequestNormalizer([])

    with pytest.raises(ResourceMappingError):
        normalizer.authorization_request(
            InvocationContext("missing"),
            ContextIdentityResolver().resolve(InvocationContext("missing")),
        )


def test_context_identity_resolver_uses_explicit_context_identity() -> None:
    identity = ContextIdentityResolver().resolve(
        {"subject": SubjectRef.user("alice")}
    )

    assert identity.authenticated
    assert identity.subject == SubjectRef.user("alice")
