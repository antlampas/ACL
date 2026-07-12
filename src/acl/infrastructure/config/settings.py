# SPDX-License-Identifier: CC-BY-SA-4.0

"""Typed configuration objects built from JSON/YAML/TOML settings."""

from __future__ import annotations

from dataclasses import dataclass, field

from acl.application import BootstrapACLConfig, SeedRule, SeedingPolicy
from acl.domain import OperationSpec
from acl.infrastructure.operations import StaticOperationCatalog


@dataclass(frozen=True, slots=True)
class ACLSettings:
    operations: dict[str, OperationSpec] = field(default_factory=dict)
    resource_roots: frozenset[str] = field(default_factory=frozenset)
    read_threshold: int = 100
    write_threshold: int = 50
    admin_threshold: int = 0
    seeding_enabled: bool = True
    seeding: dict[str, SeedRule] = field(default_factory=dict)

    def operation_catalog(self) -> StaticOperationCatalog:
        return StaticOperationCatalog(self.operations)

    def bootstrap_config(self) -> BootstrapACLConfig:
        return BootstrapACLConfig(
            resource_roots=self.resource_roots,
            read_threshold=self.read_threshold,
            write_threshold=self.write_threshold,
            admin_threshold=self.admin_threshold,
        )

    def seeding_policy(self) -> SeedingPolicy:
        return SeedingPolicy(enabled=self.seeding_enabled, rules=self.seeding)
