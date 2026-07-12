# SPDX-License-Identifier: CC-BY-SA-4.0

"""Optional SQLAlchemy 2.x repository adapter."""

from __future__ import annotations

from collections.abc import Sequence
from contextlib import AbstractContextManager

from acl.domain import (
    ACLEntry,
    ACLEntryId,
    JoinOp,
    Permission,
    ResourceRef,
    SubjectRef,
    SubjectType,
)

try:  # pragma: no cover - exercised only when SQLAlchemy is installed.
    import sqlalchemy as sa
    from sqlalchemy.engine import Engine
except ImportError:  # pragma: no cover
    sa = None  # type: ignore[assignment]
    Engine = object  # type: ignore[assignment,misc]


if sa is not None:  # pragma: no cover
    metadata = sa.MetaData()
    acl_entries_table = sa.Table(
        "acl_entries",
        metadata,
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("subject_type", sa.String(32), nullable=False),
        sa.Column("subject_id", sa.String(256), nullable=True),
        sa.Column("resource_type", sa.String(128), nullable=False),
        sa.Column("resource_id", sa.String(256), nullable=False),
        sa.Column("operation", sa.String(128), nullable=False),
        sa.Column("permission", sa.String(16), nullable=False),
        sa.Column("level", sa.BigInteger(), nullable=True),
        sa.Column("group_id", sa.String(256), nullable=True),
        sa.Column("profile_join", sa.String(8), nullable=False),
        sa.Column("subject_join", sa.String(8), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint("subject_type in ('USER', 'PUBLIC', 'SERVICE')", name="ck_acl_subject_type"),
        sa.CheckConstraint("permission in ('ALLOW', 'DENY')", name="ck_acl_permission"),
        sa.CheckConstraint("profile_join in ('AND', 'OR')", name="ck_acl_profile_join"),
        sa.CheckConstraint("subject_join in ('AND', 'OR')", name="ck_acl_subject_join"),
        sa.CheckConstraint("level is null or level >= 0", name="ck_acl_level_nonnegative"),
        sa.CheckConstraint("level is not null or group_id is not null", name="ck_acl_profile_criterion"),
        sa.CheckConstraint(
            "(subject_type = 'PUBLIC' and subject_id is null) or "
            "(subject_type <> 'PUBLIC' and subject_id is not null)",
            name="ck_acl_subject_id_shape",
        ),
        sa.CheckConstraint(
            "subject_type <> 'PUBLIC' or subject_join <> 'OR'",
            name="ck_acl_public_no_subject_or",
        ),
        sa.Index("ix_acl_resource_operation", "resource_type", "resource_id", "operation"),
        sa.Index("ix_acl_operation_resource_type", "operation", "resource_type"),
        sa.Index("ix_acl_subject", "subject_type", "subject_id"),
        sa.Index("ix_acl_group", "group_id"),
        sa.Index("ix_acl_candidate", "resource_type", "operation", "permission"),
    )
else:
    metadata = None
    acl_entries_table = None


class SqlAlchemyUnitOfWork:
    def __init__(self, engine: Engine) -> None:
        if sa is None:  # pragma: no cover
            raise RuntimeError("SQLAlchemy is required for SqlAlchemyUnitOfWork")
        self.engine = engine

    def transaction(self) -> AbstractContextManager[object]:
        return self.engine.begin()


class SqlAlchemyACLEntryRepository:
    def __init__(self, engine: Engine) -> None:
        if sa is None:  # pragma: no cover
            raise RuntimeError("SQLAlchemy is required for SqlAlchemyACLEntryRepository")
        self.engine = engine

    def create_schema(self) -> None:
        metadata.create_all(self.engine)  # type: ignore[union-attr]

    def entries_for(self, resource: ResourceRef, operation: str) -> list[ACLEntry]:
        stmt = (
            sa.select(acl_entries_table)
            .where(acl_entries_table.c.resource_type == resource.type)
            .where(acl_entries_table.c.resource_id == resource.id)
            .where(acl_entries_table.c.operation == operation.strip().upper())
            .order_by(acl_entries_table.c.id)
        )
        return self._fetch(stmt)

    def list_by_operation(self, operation: str, resource_type: str) -> list[ACLEntry]:
        stmt = (
            sa.select(acl_entries_table)
            .where(acl_entries_table.c.operation == operation.strip().upper())
            .where(acl_entries_table.c.resource_type == resource_type.strip().upper())
            .order_by(acl_entries_table.c.resource_id, acl_entries_table.c.id)
        )
        return self._fetch(stmt)

    def list_by_resource(self, resource: ResourceRef) -> list[ACLEntry]:
        stmt = (
            sa.select(acl_entries_table)
            .where(acl_entries_table.c.resource_type == resource.type)
            .where(acl_entries_table.c.resource_id == resource.id)
            .order_by(acl_entries_table.c.operation, acl_entries_table.c.id)
        )
        return self._fetch(stmt)

    def get(self, entry_id: ACLEntryId) -> ACLEntry | None:
        stmt = sa.select(acl_entries_table).where(acl_entries_table.c.id == str(entry_id))
        with self.engine.begin() as conn:
            row = conn.execute(stmt).mappings().first()
        return None if row is None else _row_to_entry(row)

    def save(self, entry: ACLEntry) -> None:
        values = _entry_to_row(entry)
        with self.engine.begin() as conn:
            updated = conn.execute(
                sa.update(acl_entries_table)
                .where(acl_entries_table.c.id == values["id"])
                .values(**{key: value for key, value in values.items() if key != "id"})
            ).rowcount
            if not updated:
                conn.execute(sa.insert(acl_entries_table).values(**values))

    def delete(self, entry_id: ACLEntryId) -> None:
        with self.engine.begin() as conn:
            conn.execute(sa.delete(acl_entries_table).where(acl_entries_table.c.id == str(entry_id)))

    def replace_entries(self, resource: ResourceRef, entries: Sequence[ACLEntry]) -> None:
        with self.engine.begin() as conn:
            conn.execute(
                sa.delete(acl_entries_table)
                .where(acl_entries_table.c.resource_type == resource.type)
                .where(acl_entries_table.c.resource_id == resource.id)
            )
            if entries:
                conn.execute(sa.insert(acl_entries_table), [_entry_to_row(entry) for entry in entries])

    def delete_by_resource(self, resource: ResourceRef) -> None:
        with self.engine.begin() as conn:
            conn.execute(
                sa.delete(acl_entries_table)
                .where(acl_entries_table.c.resource_type == resource.type)
                .where(acl_entries_table.c.resource_id == resource.id)
            )

    def delete_by_subject(self, subject: SubjectRef) -> None:
        subject_id_filter = (
            acl_entries_table.c.subject_id.is_(None)
            if subject.id is None
            else acl_entries_table.c.subject_id == subject.id
        )
        with self.engine.begin() as conn:
            conn.execute(
                sa.delete(acl_entries_table)
                .where(acl_entries_table.c.subject_type == subject.type.value)
                .where(subject_id_filter)
            )

    def is_empty(self) -> bool:
        with self.engine.begin() as conn:
            return conn.execute(sa.select(sa.func.count()).select_from(acl_entries_table)).scalar_one() == 0

    def _fetch(self, stmt: object) -> list[ACLEntry]:
        with self.engine.begin() as conn:
            rows = conn.execute(stmt).mappings().all()
        return [_row_to_entry(row) for row in rows]


def _entry_to_row(entry: ACLEntry) -> dict[str, object]:
    return {
        "id": str(entry.id),
        "subject_type": entry.subject.type.value,
        "subject_id": entry.subject.id,
        "resource_type": entry.resource.type,
        "resource_id": entry.resource.id,
        "operation": entry.operation,
        "permission": entry.permission.value,
        "level": entry.level,
        "group_id": entry.group,
        "profile_join": entry.profile_join.value,
        "subject_join": entry.subject_join.value,
    }


def _row_to_entry(row: object) -> ACLEntry:
    data = dict(row)
    return ACLEntry(
        id=ACLEntryId(str(data["id"])),
        subject=SubjectRef(
            SubjectType(str(data["subject_type"])),
            None if data.get("subject_id") is None else str(data["subject_id"]),
        ),
        resource=ResourceRef(str(data["resource_type"]), str(data["resource_id"])),
        operation=str(data["operation"]),
        permission=Permission(str(data["permission"])),
        level=None if data.get("level") is None else int(data["level"]),
        group=None if data.get("group_id") is None else str(data["group_id"]),
        profile_join=JoinOp(str(data["profile_join"])),
        subject_join=JoinOp(str(data["subject_join"])),
    )
