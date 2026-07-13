# SPDX-License-Identifier: CC-BY-SA-4.0

from __future__ import annotations

from domain import Decision, Permission, Profile, ResourceRef, SubjectRef
from tests.conftest import acl_entry, make_policy


def test_inherits_from_type_root_when_no_own_entries() -> None:
    alice = SubjectRef.user("alice")
    resource = ResourceRef("DOC", "1")
    root = ResourceRef.type_root("DOC")
    policy, _, _ = make_policy(
        entries=[acl_entry("root-view", SubjectRef.public(), root, "VIEW", group="public")]
    )

    assert policy.is_allowed(alice, "VIEW", resource) == Decision.ALLOWED


def test_own_entries_close_decision_even_when_not_matching() -> None:
    alice = SubjectRef.user("alice")
    bob = SubjectRef.user("bob")
    resource = ResourceRef("DOC", "1")
    root = ResourceRef.type_root("DOC")
    policy, _, _ = make_policy(
        entries=[
            acl_entry("root-view", SubjectRef.public(), root, "VIEW", group="public"),
            acl_entry("own-bob", bob, resource, "VIEW", level=2**31 - 1),
        ]
    )

    assert policy.is_allowed(alice, "VIEW", resource) == Decision.DENIED


def test_multi_parent_explicit_deny_blocks_other_parent_allow() -> None:
    alice = SubjectRef.user("alice")
    child = ResourceRef("DOC", "child")
    parent_a = ResourceRef("FOLDER", "a")
    parent_b = ResourceRef("FOLDER", "b")
    policy, _, _ = make_policy(
        entries=[
            acl_entry("deny-a", SubjectRef.public(), parent_a, "VIEW", Permission.DENY, group="public"),
            acl_entry("allow-b", SubjectRef.public(), parent_b, "VIEW", Permission.ALLOW, group="public"),
        ],
        parents={child: [parent_a, parent_b]},
    )

    trace = policy.explain(alice, "VIEW", child)

    assert trace.decision == Decision.DENIED
    assert trace.explicit_deny
    assert trace.reason == "parent_explicit_deny"


def test_default_deny_parent_does_not_block_other_parent_allow() -> None:
    alice = SubjectRef.user("alice")
    child = ResourceRef("DOC", "child")
    parent_a = ResourceRef("FOLDER", "a")
    parent_b = ResourceRef("FOLDER", "b")
    policy, _, _ = make_policy(
        entries=[acl_entry("allow-b", SubjectRef.public(), parent_b, "VIEW", group="public")],
        parents={child: [parent_a, parent_b]},
    )

    assert policy.is_allowed(alice, "VIEW", child) == Decision.ALLOWED


def test_non_inheritable_operation_does_not_fall_back_to_type_root() -> None:
    admin = SubjectRef.user("admin")
    resource = ResourceRef("DOC", "1")
    root = ResourceRef.type_root("DOC")
    policy, _, _ = make_policy(
        entries=[acl_entry("root-manage", SubjectRef.public(), root, "MANAGE_ACL", level=0)],
        profiles={admin: Profile(0, frozenset())},
    )

    assert policy.is_allowed(admin, "MANAGE_ACL", resource) == Decision.DENIED
    assert policy.is_allowed(admin, "MANAGE_ACL", root) == Decision.ALLOWED


def test_cycle_is_denied_without_infinite_recursion() -> None:
    alice = SubjectRef.user("alice")
    a = ResourceRef("NODE", "a")
    b = ResourceRef("NODE", "b")
    policy, _, _ = make_policy(parents={a: [b], b: [a]})

    trace = policy.explain(alice, "VIEW", a)

    assert trace.decision == Decision.DENIED
    assert a in trace.visited_resources
    assert b in trace.visited_resources


def test_candidate_resources_are_only_allow_preselection() -> None:
    alice = SubjectRef.user("alice")
    allowed = ResourceRef("DOC", "allowed")
    denied = ResourceRef("DOC", "denied")
    policy, _, _ = make_policy(
        entries=[
            acl_entry("allow", SubjectRef.public(), allowed, "VIEW", group="public"),
            acl_entry("deny", SubjectRef.public(), denied, "VIEW", Permission.DENY, group="public"),
        ]
    )

    assert policy.candidate_resources(alice, "VIEW", "DOC") == [allowed]
