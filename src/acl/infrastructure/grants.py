# SPDX-License-Identifier: CC-BY-SA-4.0

"""Grant constraint policies."""

from __future__ import annotations

from acl.domain import ACLEntry, OperationSpec, Profile
from acl.ports import RequestIdentity


class NoopGrantConstraintPolicy:
    """Default extension point; ACLService still enforces protected grants."""

    def validate_grant(
        self,
        grantor: RequestIdentity,
        grantor_profile: Profile,
        entry: ACLEntry,
        operation: OperationSpec,
    ) -> None:
        return None
