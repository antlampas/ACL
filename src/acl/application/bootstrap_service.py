# SPDX-License-Identifier: CC-BY-SA-4.0

"""Bootstrap service for the initial ACL state."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import nullcontext
from uuid import uuid4

from acl.application.dto import BootstrapACLConfig, InitialAdminInput
from acl.domain import (
    ACLEntry,
    ACLEntryId,
    ACLEntryInvariants,
    JoinOp,
    Permission,
    Profile,
    ResourceRef,
    SubjectRef,
)
from acl.ports import (
    ACLEntryRepository,
    AuditEvent,
    AuditLogger,
    OperationCatalog,
    ProfileWriter,
    UnitOfWork,
)


class _NullUnitOfWork:
    def transaction(self):
        return nullcontext()


class BootstrapService:
    def __init__(
        self,
        entries: ACLEntryRepository,
        operations: OperationCatalog,
        profile_writer: ProfileWriter | None = None,
        uow: UnitOfWork | None = None,
        audit: AuditLogger | None = None,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._entries = entries
        self._operations = operations
        self._profile_writer = profile_writer
        self._uow = uow or _NullUnitOfWork()
        self._audit = audit
        self._id_factory = id_factory or (lambda: str(uuid4()))
        self._invariants = ACLEntryInvariants()

    def ensure_bootstrap_entries(self, config: BootstrapACLConfig) -> None:
        if not self._entries.is_empty():
            return
        entries: list[ACLEntry] = []
        system = ResourceRef.system()
        for operation in sorted(config.admin_operations):
            self._operations.require(operation)
            entries.append(self._entry(system, operation, level=config.admin_threshold))
        for operation in sorted(config.global_write_operations):
            self._operations.require(operation)
            entries.append(self._entry(system, operation, level=config.write_threshold))
        for root in sorted(config.resource_roots):
            resource = ResourceRef.type_root(root)
            for operation in sorted(config.read_operations):
                self._operations.require(operation)
                entries.append(
                    self._entry(
                        resource,
                        operation,
                        level=None if root in config.public_read_roots else config.read_threshold,
                        group="public" if root in config.public_read_roots else None,
                    )
                )
            for operation in sorted(config.write_operations):
                self._operations.require(operation)
                entries.append(self._entry(resource, operation, level=config.write_threshold))
        for entry in entries:
            spec = self._operations.require(entry.operation)
            self._invariants.validate(entry, spec)
        with self._uow.transaction():
            for entry in entries:
                self._entries.save(entry)
        self._audit_event("BOOTSTRAP_COMPLETED", {"entries": str(len(entries))})

    def create_initial_admin(self, input: InitialAdminInput) -> SubjectRef:
        if self._profile_writer is not None:
            self._profile_writer.set_profile(
                input.subject,
                Profile(level=input.level, groups=input.groups),
            )
        self._audit_event("INITIAL_ADMIN_CREATED", {"subject": str(input.subject)})
        return input.subject

    def _entry(
        self,
        resource: ResourceRef,
        operation: str,
        level: int | None,
        group: str | None = None,
    ) -> ACLEntry:
        return ACLEntry(
            id=ACLEntryId(self._id_factory()),
            subject=SubjectRef.public(),
            resource=resource,
            operation=operation,
            permission=Permission.ALLOW,
            level=level,
            group=group,
            profile_join=JoinOp.OR,
            subject_join=JoinOp.AND,
        )

    def _audit_event(self, event_type: str, detail: dict[str, str]) -> None:
        if self._audit is None:
            return
        self._audit.append(AuditEvent(type=event_type, detail=detail))
