# SPDX-License-Identifier: CC-BY-SA-4.0

"""Application DTOs used by ACL services and request adapters."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from acl.domain import (
    ACLEntry,
    ACLEntryId,
    Decision,
    JoinOp,
    Permission,
    Profile,
    ResourceRef,
    SubjectRef,
)
from acl.ports import RequestIdentity


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    identity: RequestIdentity
    operation: str
    resource: ResourceRef
    metadata: Mapping[str, str] | None = None


@dataclass(frozen=True, slots=True)
class CandidateResourcesRequest:
    identity: RequestIdentity
    operation: str
    resource_type: str
    metadata: Mapping[str, str] | None = None


@dataclass(frozen=True, slots=True)
class DecisionTrace:
    subject: SubjectRef
    profile: Profile
    operation: str
    resource: ResourceRef
    decision: Decision
    reason: str
    explicit_deny: bool = False
    matched_entry_ids: tuple[ACLEntryId, ...] = ()
    visited_resources: tuple[ResourceRef, ...] = ()


@dataclass(frozen=True, slots=True)
class ACLEntryInput:
    subject: SubjectRef
    resource: ResourceRef
    operation: str
    permission: Permission
    level: int | None = None
    group: str | None = None
    profile_join: JoinOp = JoinOp.OR
    subject_join: JoinOp = JoinOp.AND
    id: ACLEntryId | None = None


@dataclass(frozen=True, slots=True)
class ACLEntryPatch:
    subject: SubjectRef | None = None
    resource: ResourceRef | None = None
    operation: str | None = None
    permission: Permission | None = None
    level: int | None = None
    group: str | None = None
    profile_join: JoinOp | None = None
    subject_join: JoinOp | None = None
    clear_level: bool = False
    clear_group: bool = False


@dataclass(frozen=True, slots=True)
class ACLEntryDTO:
    id: ACLEntryId
    subject: SubjectRef
    resource: ResourceRef
    operation: str
    permission: Permission
    level: int | None
    group: str | None
    profile_join: JoinOp
    subject_join: JoinOp

    @staticmethod
    def from_entry(entry: ACLEntry) -> "ACLEntryDTO":
        return ACLEntryDTO(
            id=entry.id,
            subject=entry.subject,
            resource=entry.resource,
            operation=entry.operation,
            permission=entry.permission,
            level=entry.level,
            group=entry.group,
            profile_join=entry.profile_join,
            subject_join=entry.subject_join,
        )


@dataclass(frozen=True, slots=True)
class SeedRule:
    resource_type: str
    operations: frozenset[str]
    grant_to: str = "CREATOR"
    level_strategy: str = "UNIVERSAL"
    fixed_level: int | None = None
    group: str | None = None

    def __post_init__(self) -> None:
        resource_type = str(self.resource_type).strip().upper()
        operations = frozenset(str(operation).strip().upper() for operation in self.operations)
        grant_to = str(self.grant_to).strip().upper()
        level_strategy = str(self.level_strategy).strip().upper()
        if not resource_type:
            raise ValueError("seed rule resource_type must be non-empty")
        if grant_to not in {"CREATOR", "CREATOR_GROUP", "NONE"}:
            raise ValueError("grant_to must be CREATOR, CREATOR_GROUP or NONE")
        if level_strategy not in {"UNIVERSAL", "CREATOR_LEVEL", "FIXED"}:
            raise ValueError("level_strategy must be UNIVERSAL, CREATOR_LEVEL or FIXED")
        if level_strategy == "FIXED" and self.fixed_level is None:
            raise ValueError("FIXED seed rules require fixed_level")
        object.__setattr__(self, "resource_type", resource_type)
        object.__setattr__(self, "operations", operations)
        object.__setattr__(self, "grant_to", grant_to)
        object.__setattr__(self, "level_strategy", level_strategy)
        if self.group is not None:
            object.__setattr__(self, "group", str(self.group).strip())


@dataclass(frozen=True, slots=True)
class SeedingPolicy:
    enabled: bool = False
    rules: Mapping[str, SeedRule] = field(default_factory=dict)

    def rule_for(self, resource_type: str) -> SeedRule | None:
        return self.rules.get(str(resource_type).strip().upper())


@dataclass(frozen=True, slots=True)
class BootstrapACLConfig:
    resource_roots: frozenset[str] = field(default_factory=frozenset)
    read_threshold: int = 100
    write_threshold: int = 50
    admin_threshold: int = 0
    read_operations: frozenset[str] = frozenset({"LIST", "VIEW"})
    write_operations: frozenset[str] = frozenset({"EDIT", "DELETE"})
    admin_operations: frozenset[str] = frozenset(
        {"MANAGE_ACL", "MANAGE_PROFILES", "MANAGE_IDENTITIES", "MANAGE_ACCOUNTS"}
    )
    global_write_operations: frozenset[str] = frozenset({"CREATE", "EXECUTE"})
    public_read_roots: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "resource_roots",
            frozenset(str(root).strip().upper() for root in self.resource_roots if str(root).strip()),
        )
        for field_name in (
            "read_operations",
            "write_operations",
            "admin_operations",
            "global_write_operations",
            "public_read_roots",
        ):
            values = getattr(self, field_name)
            object.__setattr__(
                self,
                field_name,
                frozenset(str(value).strip().upper() for value in values if str(value).strip()),
            )


@dataclass(frozen=True, slots=True)
class InitialAdminInput:
    subject: SubjectRef
    level: int = 0
    groups: frozenset[str] = frozenset({"admins"})
