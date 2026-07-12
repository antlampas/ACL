# SPDX-License-Identifier: CC-BY-SA-4.0

"""Small identity resolvers for tests and framework adapters."""

from __future__ import annotations

from collections.abc import Mapping

from acl.domain import SubjectRef
from acl.ports import PrincipalBindingPort, RequestIdentity


class StaticIdentityResolver:
    def __init__(self, identity: RequestIdentity | None = None) -> None:
        self._identity = identity or RequestIdentity.anonymous("static")

    def resolve(self, context: object) -> RequestIdentity:
        return self._identity


class ContextIdentityResolver:
    def __init__(self, binding: PrincipalBindingPort | None = None) -> None:
        self._binding = binding

    def resolve(self, context: object) -> RequestIdentity:
        identity = _get(context, "identity")
        if isinstance(identity, RequestIdentity):
            return identity

        principal_id = _get(context, "principal_id")
        if principal_id is not None and self._binding is not None:
            subject = self._binding.bind(str(principal_id))
            if subject is not None:
                return RequestIdentity(
                    subject=subject,
                    authenticated=True,
                    auth_method="principal_binding",
                    principal_id=str(principal_id),
                )

        subject = _get(context, "subject")
        if isinstance(subject, SubjectRef):
            return RequestIdentity(subject=subject, authenticated=True, auth_method="context")
        return RequestIdentity.anonymous("context")


def _get(context: object, name: str) -> object | None:
    if isinstance(context, Mapping):
        return context.get(name)
    return getattr(context, name, None)
