# SPDX-License-Identifier: CC-BY-SA-4.0

"""A small generic invocation context for adapter tests and demos."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from acl.ports import RequestIdentity


@dataclass(frozen=True, slots=True)
class InvocationContext:
    selector: str
    attributes: Mapping[str, object] = field(default_factory=dict)
    resource_ids: Mapping[str, object] = field(default_factory=dict)
    identity: RequestIdentity | None = None
    principal_id: str | None = None
