# SPDX-License-Identifier: CC-BY-SA-4.0

"""Application facade for normalized authorization requests."""

from __future__ import annotations

from acl.application.authorization_policy import AuthorizationPolicy
from acl.application.dto import AuthorizationRequest, CandidateResourcesRequest, DecisionTrace
from acl.domain import AuthorizationDenied, Decision, ResourceRef
from acl.ports import AuditEvent, AuditLogger


class AuthorizationService:
    def __init__(
        self,
        policy: AuthorizationPolicy,
        audit: AuditLogger | None = None,
    ) -> None:
        self._policy = policy
        self._audit = audit

    def is_allowed(self, request: AuthorizationRequest) -> bool:
        return self._policy.is_allowed(
            request.identity.subject,
            request.operation,
            request.resource,
        ) == Decision.ALLOWED

    def require(self, request: AuthorizationRequest) -> None:
        trace = self.explain(request)
        if trace.decision == Decision.ALLOWED:
            return
        if self._audit is not None:
            self._audit.append(
                AuditEvent(
                    type="AUTHZ_DENIED",
                    actor=_actor(request.identity.subject),
                    resource=_resource(request.resource),
                    detail={"operation": trace.operation, "reason": trace.reason},
                )
            )
        raise AuthorizationDenied(trace=trace)

    def candidate_resources(self, request: CandidateResourcesRequest) -> list[ResourceRef]:
        return self._policy.candidate_resources(
            request.identity.subject,
            request.operation,
            request.resource_type,
        )

    def explain(self, request: AuthorizationRequest) -> DecisionTrace:
        return self._policy.explain(
            request.identity.subject,
            request.operation,
            request.resource,
        )


def _actor(subject: object) -> str:
    return str(subject)


def _resource(resource: ResourceRef) -> str:
    return f"{resource.type}:{resource.id}"
