# SPDX-License-Identifier: CC-BY-SA-4.0

"""Grant constraint strategy port."""

from __future__ import annotations

from typing import Protocol

from acl.domain import ACLEntry, OperationSpec, Profile
from .identity import RequestIdentity


class GrantConstraintPolicy(Protocol):
    def validate_grant(
        self,
        grantor: RequestIdentity,
        grantor_profile: Profile,
        entry: ACLEntry,
        operation: OperationSpec,
    ) -> None: ...
