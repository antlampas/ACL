# SPDX-License-Identifier: CC-BY-SA-4.0

from __future__ import annotations

import pytest

from domain import (
    ACLEntry,
    ACLEntryId,
    ACLEntryInvariants,
    ACLValidationError,
    Decision,
    JoinOp,
    Permission,
    Profile,
    ResourceRef,
    SubjectRef,
    entry_matches,
    resolve,
)
from infrastructure.operations import default_operation_catalog


def test_profile_always_contains_public_group() -> None:
    profile = Profile(level=10, groups=frozenset({"editors"}))

    assert profile.groups == frozenset({"editors", "public"})
    assert profile.stored_groups() == frozenset({"editors"})


def test_level_orientation_and_group_matching() -> None:
    entry = ACLEntry(
        id=ACLEntryId("entry-1"),
        subject=SubjectRef.public(),
        resource=ResourceRef("DOC", "1"),
        operation="VIEW",
        permission=Permission.ALLOW,
        level=50,
        group="editors",
        profile_join=JoinOp.AND,
    )

    assert entry_matches(entry, SubjectRef.user("alice"), Profile(10, frozenset({"editors"})))
    assert not entry_matches(entry, SubjectRef.user("bob"), Profile(60, frozenset({"editors"})))


def test_deny_overrides_allow() -> None:
    subject = SubjectRef.user("alice")
    resource = ResourceRef("DOC", "1")
    entries = [
        ACLEntry(ACLEntryId("allow"), subject, resource, "VIEW", Permission.ALLOW, level=100),
        ACLEntry(ACLEntryId("deny"), subject, resource, "VIEW", Permission.DENY, level=100),
    ]

    result = resolve(entries, subject, Profile(10, frozenset()))

    assert result.decision == Decision.DENIED
    assert result.explicit_deny


def test_structural_invariant_requires_profile_criterion(catalog) -> None:
    entry = ACLEntry(
        id=ACLEntryId("entry-1"),
        subject=SubjectRef.user("alice"),
        resource=ResourceRef("DOC", "1"),
        operation="VIEW",
        permission=Permission.ALLOW,
    )

    with pytest.raises(ACLValidationError, match="INV-1"):
        ACLEntryInvariants().validate(entry, catalog.require("VIEW"))


def test_public_mutating_entry_that_matches_anonymous_is_rejected(catalog) -> None:
    entry = ACLEntry(
        id=ACLEntryId("entry-1"),
        subject=SubjectRef.public(),
        resource=ResourceRef("DOC", "1"),
        operation="EDIT",
        permission=Permission.ALLOW,
        group="public",
    )

    with pytest.raises(ACLValidationError, match="INV-2"):
        ACLEntryInvariants().validate(entry, catalog.require("EDIT"))


def test_public_mutating_entry_for_non_public_group_is_valid(catalog) -> None:
    entry = ACLEntry(
        id=ACLEntryId("entry-1"),
        subject=SubjectRef.public(),
        resource=ResourceRef("DOC", "1"),
        operation="EDIT",
        permission=Permission.ALLOW,
        group="editors",
    )

    ACLEntryInvariants().validate(entry, catalog.require("EDIT"))


def test_public_subject_join_or_is_rejected(catalog) -> None:
    entry = ACLEntry(
        id=ACLEntryId("entry-1"),
        subject=SubjectRef.public(),
        resource=ResourceRef("DOC", "1"),
        operation="VIEW",
        permission=Permission.ALLOW,
        group="public",
        subject_join=JoinOp.OR,
    )

    with pytest.raises(ACLValidationError, match="INV-5"):
        ACLEntryInvariants().validate(entry, catalog.require("VIEW"))
