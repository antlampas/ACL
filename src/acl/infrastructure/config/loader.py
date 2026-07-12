# SPDX-License-Identifier: CC-BY-SA-4.0

"""Small config loader with stdlib JSON/TOML and optional PyYAML support."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any

from acl.application import SeedRule
from acl.domain import OperationSpec
from acl.infrastructure.config.settings import ACLSettings
from acl.infrastructure.operations import default_operation_catalog


def load_acl_settings(path: str | Path) -> ACLSettings:
    path = Path(path)
    data = _load_mapping(path)
    acl = data.get("acl", data)
    default_catalog = default_operation_catalog()
    operations = {spec.name: spec for spec in default_catalog.all()}
    operations.update(_parse_operations(acl.get("operations", {})))
    seeding = _parse_seeding(acl.get("seeding", {}))
    return ACLSettings(
        operations=operations,
        resource_roots=frozenset(acl.get("resource_roots", ())),
        read_threshold=int(acl.get("read_threshold", 100)),
        write_threshold=int(acl.get("write_threshold", 50)),
        admin_threshold=int(acl.get("admin_threshold", 0)),
        seeding_enabled=bool(acl.get("seeding_enabled", True)),
        seeding=seeding,
    )


def _load_mapping(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    with path.open("rb") as fh:
        if suffix == ".json":
            return json.load(fh)
        if suffix == ".toml":
            return tomllib.load(fh)
        if suffix in {".yaml", ".yml"}:
            try:
                import yaml  # type: ignore[import-not-found]
            except ImportError as exc:
                raise RuntimeError("PyYAML is required to load YAML ACL settings") from exc
            return yaml.safe_load(fh) or {}
    raise ValueError(f"unsupported ACL settings format: {path.suffix}")


def _parse_operations(data: dict[str, Any]) -> dict[str, OperationSpec]:
    operations: dict[str, OperationSpec] = {}
    for name, item in data.items():
        operations[str(name).strip().upper()] = OperationSpec(
            name=str(name),
            read_only=bool(item["read_only"]),
            inheritable=bool(item.get("inheritable", True)),
            protected=bool(item.get("protected", False)),
        )
    return operations


def _parse_seeding(data: dict[str, Any]) -> dict[str, SeedRule]:
    rules: dict[str, SeedRule] = {}
    for resource_type, item in data.items():
        rule = SeedRule(
            resource_type=str(resource_type),
            operations=frozenset(item.get("operations", ())),
            grant_to=str(item.get("grant_to", "CREATOR")),
            level_strategy=str(item.get("level_strategy", "UNIVERSAL")),
            fixed_level=item.get("fixed_level"),
            group=item.get("group"),
        )
        rules[rule.resource_type] = rule
    return rules
