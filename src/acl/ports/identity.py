# SPDX-License-Identifier: CC-BY-SA-4.0

"""Identity ports. Authentication happens outside the ACL decision core."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from acl.domain import SubjectRef


@dataclass(frozen=True, slots=True)
class RequestIdentity:
    subject: SubjectRef
    authenticated: bool
    auth_method: str | None = None
    authz_version: int | None = None
    principal_id: str | None = None
    credential_ref: str | None = None

    @staticmethod
    def anonymous(auth_method: str | None = None) -> "RequestIdentity":
        return RequestIdentity(
            subject=SubjectRef.public(),
            authenticated=False,
            auth_method=auth_method,
        )


class IdentityResolver(Protocol):
    def resolve(self, context: object) -> RequestIdentity: ...


class PrincipalBindingPort(Protocol):
    def bind(self, principal_id: str) -> SubjectRef | None: ...
