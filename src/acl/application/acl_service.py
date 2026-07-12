# SPDX-License-Identifier: CC-BY-SA-4.0

"""ACL entry management service."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from contextlib import nullcontext
from uuid import uuid4

from acl.application.authorization_policy import AuthorizationPolicy
from acl.application.dto import ACLEntryDTO, ACLEntryInput, ACLEntryPatch, SeedRule, SeedingPolicy
from acl.domain import (
    ACLEntry,
    ACLEntryId,
    ACLEntryInvariants,
    ACLValidationError,
    ANON_SENTINEL,
    Decision,
    GrantConstraintError,
    JoinOp,
    Permission,
    Profile,
    ResourceRef,
    SubjectRef,
    SubjectType,
)
from acl.ports import (
    ACLEntryRepository,
    AuditEvent,
    AuditLogger,
    GrantConstraintPolicy,
    OperationCatalog,
    ProfileProvider,
    RequestIdentity,
    UnitOfWork,
)


class _NoopGrantConstraintPolicy:
    def validate_grant(
        self,
        grantor: RequestIdentity,
        grantor_profile: Profile,
        entry: ACLEntry,
        operation: object,
    ) -> None:
        return None


class _NullUnitOfWork:
    def transaction(self):
        return nullcontext()


class ACLService:
    def __init__(
        self,
        entries: ACLEntryRepository,
        policy: AuthorizationPolicy,
        profiles: ProfileProvider,
        operations: OperationCatalog,
        grant_constraints: GrantConstraintPolicy | None = None,
        uow: UnitOfWork | None = None,
        audit: AuditLogger | None = None,
        seeding_policy: SeedingPolicy | None = None,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._entries = entries
        self._policy = policy
        self._profiles = profiles
        self._operations = operations
        self._grant_constraints = grant_constraints or _NoopGrantConstraintPolicy()
        self._uow = uow or _NullUnitOfWork()
        self._audit_logger = audit
        self._seeding_policy = seeding_policy or SeedingPolicy()
        self._id_factory = id_factory or (lambda: str(uuid4()))
        self._invariants = ACLEntryInvariants()

    def list_entries(self, identity: RequestIdentity, resource: ResourceRef) -> list[ACLEntryDTO]:
        self._ensure_can_manage(identity, resource)
        return [ACLEntryDTO.from_entry(entry) for entry in self._entries.list_by_resource(resource)]

    def create_entry(self, identity: RequestIdentity, input: ACLEntryInput) -> ACLEntryDTO:
        entry = self._entry_from_input(input)
        spec = self._operations.require(entry.operation)
        self._ensure_can_manage(identity, entry.resource)
        self._validate_and_check_grant(identity, entry)
        with self._uow.transaction():
            self._entries.save(entry)
        self._audit_entry("ACL_ENTRY_CREATED", identity.subject, entry)
        return ACLEntryDTO.from_entry(entry)

    def update_entry(
        self,
        identity: RequestIdentity,
        entry_id: ACLEntryId,
        patch: ACLEntryPatch,
    ) -> ACLEntryDTO:
        current = self._entries.get(entry_id)
        if current is None:
            raise ACLValidationError(f"ACL entry {entry_id!r} does not exist")
        updated = self._patched_entry(current, patch)
        self._operations.require(updated.operation)
        self._ensure_can_manage(identity, current.resource)
        if updated.resource != current.resource:
            self._ensure_can_manage(identity, updated.resource)
        self._validate_and_check_grant(identity, updated)
        with self._uow.transaction():
            self._entries.save(updated)
        self._audit_entry("ACL_ENTRY_UPDATED", identity.subject, updated)
        return ACLEntryDTO.from_entry(updated)

    def delete_entry(self, identity: RequestIdentity, entry_id: ACLEntryId) -> None:
        entry = self._entries.get(entry_id)
        if entry is None:
            raise ACLValidationError(f"ACL entry {entry_id!r} does not exist")
        self._ensure_can_manage(identity, entry.resource)
        with self._uow.transaction():
            self._entries.delete(entry_id)
        self._audit_entry("ACL_ENTRY_DELETED", identity.subject, entry)

    def replace_entries(
        self,
        identity: RequestIdentity,
        resource: ResourceRef,
        inputs: Sequence[ACLEntryInput],
    ) -> None:
        self._ensure_can_manage(identity, resource)
        entries = [self._entry_from_input(input) for input in inputs]
        for entry in entries:
            if entry.resource != resource:
                raise ACLValidationError("replace_entries inputs must target the requested resource")
            self._validate_and_check_grant(identity, entry)
        with self._uow.transaction():
            self._entries.replace_entries(resource, entries)
        self._emit_audit(
            "ACL_ENTRIES_REPLACED",
            actor=identity.subject,
            resource=resource,
            detail={"count": str(len(entries))},
        )

    def delete_by_resource(self, resource: ResourceRef) -> None:
        with self._uow.transaction():
            self._entries.delete_by_resource(resource)
        self._emit_audit("ACL_ENTRIES_DELETED_BY_RESOURCE", resource=resource)

    def delete_by_subject(self, subject: SubjectRef) -> None:
        with self._uow.transaction():
            self._entries.delete_by_subject(subject)
        self._emit_audit("ACL_ENTRIES_DELETED_BY_SUBJECT", actor=subject)

    def on_resource_created(
        self,
        resource: ResourceRef,
        creator: SubjectRef,
        resource_type: str,
    ) -> None:
        rule = self._seeding_policy.rule_for(resource_type)
        if not self._seeding_policy.enabled or rule is None or rule.grant_to == "NONE":
            return
        if creator.type == SubjectType.PUBLIC:
            return
        entries = [self._seed_entry(resource, creator, rule, operation) for operation in rule.operations]
        for entry in entries:
            spec = self._operations.require(entry.operation)
            self._invariants.validate(entry, spec)
        with self._uow.transaction():
            for entry in entries:
                self._entries.save(entry)
        self._emit_audit(
            "ACL_SEEDING_COMPLETED",
            actor=creator,
            resource=resource,
            detail={"count": str(len(entries))},
        )

    def _entry_from_input(self, input: ACLEntryInput) -> ACLEntry:
        level = input.level
        group = input.group
        if level is None and group is None:
            if input.subject.type == SubjectType.PUBLIC:
                group = "public"
            else:
                level = ANON_SENTINEL
        return ACLEntry(
            id=input.id or ACLEntryId(self._id_factory()),
            subject=input.subject,
            resource=input.resource,
            operation=input.operation,
            permission=input.permission,
            level=level,
            group=group,
            profile_join=input.profile_join,
            subject_join=input.subject_join,
        )

    def _patched_entry(self, entry: ACLEntry, patch: ACLEntryPatch) -> ACLEntry:
        level = None if patch.clear_level else (entry.level if patch.level is None else patch.level)
        group = None if patch.clear_group else (entry.group if patch.group is None else patch.group)
        return ACLEntry(
            id=entry.id,
            subject=patch.subject or entry.subject,
            resource=patch.resource or entry.resource,
            operation=patch.operation or entry.operation,
            permission=patch.permission or entry.permission,
            level=level,
            group=group,
            profile_join=patch.profile_join or entry.profile_join,
            subject_join=patch.subject_join or entry.subject_join,
        )

    def _validate_and_check_grant(self, identity: RequestIdentity, entry: ACLEntry) -> None:
        spec = self._operations.require(entry.operation)
        self._invariants.validate(entry, spec)
        if entry.permission != Permission.ALLOW:
            return
        grantor_profile = self._profiles.profile_of(identity.subject)
        has_global_manage = self._has_global_manage(identity.subject)
        if spec.protected and not has_global_manage:
            self._audit_grant_rejected(identity.subject, entry, "protected_operation_requires_global_manage")
            raise GrantConstraintError("protected operation grants require MANAGE_ACL on SYSTEM:global")
        if entry.level is not None and entry.level < grantor_profile.level and not has_global_manage:
            self._audit_grant_rejected(identity.subject, entry, "level_escalation_requires_global_manage")
            raise GrantConstraintError("cannot grant a level more privileged than the grantor profile")
        self._grant_constraints.validate_grant(identity, grantor_profile, entry, spec)

    def _ensure_can_manage(self, identity: RequestIdentity, resource: ResourceRef) -> None:
        if resource.is_system or resource.is_type_root:
            if not self._has_global_manage(identity.subject):
                raise GrantConstraintError("SYSTEM:global and type roots require global MANAGE_ACL")
            return
        if self._has_global_manage(identity.subject):
            return
        if self._policy.is_allowed(identity.subject, "MANAGE_ACL", resource) != Decision.ALLOWED:
            raise GrantConstraintError("MANAGE_ACL is required on the resource or SYSTEM:global")

    def _has_global_manage(self, subject: SubjectRef) -> bool:
        return self._policy.is_allowed(subject, "MANAGE_ACL", ResourceRef.system()) == Decision.ALLOWED

    def _seed_entry(
        self,
        resource: ResourceRef,
        creator: SubjectRef,
        rule: SeedRule,
        operation: str,
    ) -> ACLEntry:
        if rule.level_strategy == "UNIVERSAL":
            level = ANON_SENTINEL
        elif rule.level_strategy == "CREATOR_LEVEL":
            level = self._profiles.profile_of(creator).level
        else:
            level = rule.fixed_level
        subject = creator
        group = None
        if rule.grant_to == "CREATOR_GROUP":
            subject = SubjectRef.public()
            group = rule.group
            if not group:
                raise ACLValidationError("CREATOR_GROUP seed rules require a group")
        return ACLEntry(
            id=ACLEntryId(self._id_factory()),
            subject=subject,
            resource=resource,
            operation=operation,
            permission=Permission.ALLOW,
            level=level,
            group=group,
            profile_join=JoinOp.OR,
            subject_join=JoinOp.AND,
        )

    def _audit_entry(self, event_type: str, actor: SubjectRef, entry: ACLEntry) -> None:
        self._emit_audit(
            event_type,
            actor=actor,
            resource=entry.resource,
            entry_id=entry.id,
            detail={"operation": entry.operation, "permission": entry.permission.value},
        )

    def _audit_grant_rejected(self, actor: SubjectRef, entry: ACLEntry, reason: str) -> None:
        self._emit_audit(
            "GRANT_REJECTED",
            actor=actor,
            resource=entry.resource,
            entry_id=entry.id,
            detail={"operation": entry.operation, "reason": reason},
        )

    def _emit_audit(
        self,
        event_type: str,
        actor: SubjectRef | None = None,
        resource: ResourceRef | None = None,
        entry_id: ACLEntryId | None = None,
        detail: dict[str, str] | None = None,
    ) -> None:
        if self._audit_logger is None:
            return
        self._audit_logger.append(
            AuditEvent(
                type=event_type,
                actor=str(actor) if actor is not None else None,
                resource=f"{resource.type}:{resource.id}" if resource is not None else None,
                entry_id=str(entry_id) if entry_id is not None else None,
                detail=detail or {},
            )
        )
