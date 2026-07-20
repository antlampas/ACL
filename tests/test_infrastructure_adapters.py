# SPDX-License-Identifier: CC-BY-SA-4.0
"""Integrazione degli adapter infrastrutturali (IMPLEMENTATION.md §14.6).

Coprono i percorsi non esercitati dai repository in memoria: SQLAlchemy (schema,
vincoli, BIGINT, upsert, replace atomico), repository JSON su file e loader di
configurazione YAML. Le dipendenze opzionali sono saltate se assenti.
"""
from __future__ import annotations

import pytest

from application import AuthorizationPolicy
from domain import ANON_SENTINEL, Decision, Permission, Profile, ResourceRef, SubjectRef
from infrastructure.operations import default_operation_catalog
from infrastructure.persistence.file_json import JsonFileACLEntryRepository
from infrastructure.profiles import InMemoryProfileProvider
from infrastructure.resources import StaticResourceHierarchyProvider
from tests.conftest import acl_entry


# --- SQLAlchemy ---------------------------------------------------------------


@pytest.fixture
def sql_repo():
    sa = pytest.importorskip("sqlalchemy")
    from infrastructure.persistence.sqlalchemy import SqlAlchemyACLEntryRepository

    engine = sa.create_engine("sqlite://")
    repo = SqlAlchemyACLEntryRepository(engine)
    repo.create_schema()
    return repo, engine, sa


def test_sqlalchemy_crud_roundtrip_and_bigint_sentinel(sql_repo) -> None:
    repo, _engine, _sa = sql_repo
    assert repo.is_empty()

    alice = acl_entry("e-alice", SubjectRef.user("alice"), ResourceRef("DOC", "1"), "VIEW", level=ANON_SENTINEL)
    repo.save(alice)

    assert not repo.is_empty()
    stored = repo.get("e-alice")
    assert stored == alice
    # BIGINT: il sentinel (INT_MAX a 32 bit) e' preservato senza overflow.
    assert stored.level == ANON_SENTINEL
    assert [e.id for e in repo.entries_for(ResourceRef("DOC", "1"), "VIEW")] == ["e-alice"]


def test_sqlalchemy_save_is_idempotent_upsert(sql_repo) -> None:
    repo, _engine, _sa = sql_repo
    resource = ResourceRef("DOC", "1")
    repo.save(acl_entry("e1", SubjectRef.user("alice"), resource, "VIEW", level=ANON_SENTINEL))
    repo.save(acl_entry("e1", SubjectRef.user("alice"), resource, "VIEW", Permission.DENY, level=ANON_SENTINEL))

    entries = repo.entries_for(resource, "VIEW")
    assert len(entries) == 1
    assert entries[0].permission == Permission.DENY


def test_sqlalchemy_replace_entries_is_atomic_per_resource(sql_repo) -> None:
    repo, _engine, _sa = sql_repo
    resource = ResourceRef("DOC", "1")
    repo.save(acl_entry("old", SubjectRef.public(), resource, "VIEW", group="editors"))

    repo.replace_entries(resource, [acl_entry("new", SubjectRef.public(), resource, "VIEW", group="public")])

    entries = repo.entries_for(resource, "VIEW")
    assert [e.id for e in entries] == ["new"]


def test_sqlalchemy_check_constraints_reject_invalid_rows(sql_repo) -> None:
    repo, engine, sa = sql_repo
    from infrastructure.persistence.sqlalchemy import acl_entries_table

    # INV-1 strutturale a livello DB: senza level ne' group.
    with pytest.raises(sa.exc.IntegrityError):
        with engine.begin() as conn:
            conn.execute(
                sa.insert(acl_entries_table).values(
                    id="bad", subject_type="USER", subject_id="x",
                    resource_type="DOC", resource_id="9", operation="VIEW",
                    permission="ALLOW", level=None, group_id=None,
                    profile_join="OR", subject_join="AND",
                )
            )

    # INV-5 strutturale a livello DB: PUBLIC con subject_join OR.
    with pytest.raises(sa.exc.IntegrityError):
        with engine.begin() as conn:
            conn.execute(
                sa.insert(acl_entries_table).values(
                    id="bad2", subject_type="PUBLIC", subject_id=None,
                    resource_type="DOC", resource_id="9", operation="VIEW",
                    permission="ALLOW", level=1, group_id=None,
                    profile_join="OR", subject_join="OR",
                )
            )


def test_sqlalchemy_repository_backs_the_policy(sql_repo) -> None:
    repo, _engine, _sa = sql_repo
    repo.save(acl_entry("a", SubjectRef.user("alice"), ResourceRef("DOC", "1"), "VIEW", level=ANON_SENTINEL))
    profiles = InMemoryProfileProvider({SubjectRef.user("alice"): Profile(50, frozenset())})
    policy = AuthorizationPolicy(
        repo, profiles, StaticResourceHierarchyProvider(include_type_roots=False), default_operation_catalog()
    )

    assert policy.is_allowed(SubjectRef.user("alice"), "VIEW", ResourceRef("DOC", "1")) == Decision.ALLOWED
    assert policy.is_allowed(SubjectRef.user("bob"), "VIEW", ResourceRef("DOC", "1")) == Decision.DENIED


# --- JSON file ----------------------------------------------------------------


def test_json_file_repository_roundtrips_on_disk(tmp_path) -> None:
    path = tmp_path / "acl.json"
    writer = JsonFileACLEntryRepository(path)
    writer.save(acl_entry("e-alice", SubjectRef.user("alice"), ResourceRef("DOC", "1"), "VIEW", level=ANON_SENTINEL))
    writer.save(acl_entry("e-admin", SubjectRef.public(), ResourceRef.system(), "MANAGE_ACL", level=0))
    assert path.exists()

    reloaded = JsonFileACLEntryRepository(path)
    assert {e.id for e in reloaded.all_entries()} == {"e-alice", "e-admin"}
    assert reloaded.get("e-alice").level == ANON_SENTINEL


def test_json_file_repository_writes_atomically_without_leftover_tmp(tmp_path) -> None:
    path = tmp_path / "acl.json"
    repo = JsonFileACLEntryRepository(path)
    repo.save(acl_entry("e1", SubjectRef.public(), ResourceRef("DOC", "1"), "VIEW", group="public"))

    # il rename atomico non lascia file temporanei residui
    assert list(tmp_path.glob("*.tmp")) == []


# --- Loader YAML --------------------------------------------------------------


def test_yaml_loader_merges_custom_operations_and_seeding(tmp_path) -> None:
    pytest.importorskip("yaml")
    from infrastructure.config.loader import load_acl_settings

    config = tmp_path / "acl.yaml"
    config.write_text(
        """
acl:
  read_threshold: 77
  seeding_enabled: true
  operations:
    PUBLISH:
      read_only: false
      inheritable: true
      protected: false
  resource_roots:
    - DOC
  seeding:
    DOC:
      operations: [VIEW, EDIT]
      grant_to: CREATOR
      level_strategy: UNIVERSAL
""",
        encoding="utf-8",
    )

    settings = load_acl_settings(config)

    assert settings.read_threshold == 77
    assert "PUBLISH" in settings.operations
    assert "VIEW" in settings.operations  # i default restano
    assert settings.operation_catalog().require("PUBLISH").name == "PUBLISH"
    assert settings.seeding["DOC"].operations == frozenset({"VIEW", "EDIT"})
    assert settings.seeding_policy().rule_for("DOC") is not None
