# SPDX-License-Identifier: CC-BY-SA-4.0

"""Rule-based request normalizer that fails closed on ambiguous input."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from acl.application import AuthorizationRequest, CandidateResourcesRequest
from acl.domain import ResourceMappingError, ResourceRef
from acl.ports import RequestIdentity


@dataclass(frozen=True, slots=True)
class RequestMappingRule:
    selector: str
    operation: str
    resource_type: str | None = None
    resource_id_source: str | None = None
    service_enforced: bool = False
    fallback_protected: bool = False

    def __post_init__(self) -> None:
        selector = str(self.selector).strip()
        operation = str(self.operation).strip().upper()
        if not selector:
            raise ValueError("selector must be non-empty")
        if not operation:
            raise ValueError("operation must be non-empty")
        object.__setattr__(self, "selector", selector)
        object.__setattr__(self, "operation", operation)
        if self.resource_type is not None:
            object.__setattr__(self, "resource_type", str(self.resource_type).strip().upper())


class MappingRequestNormalizer:
    def __init__(
        self,
        rules: Mapping[str, RequestMappingRule] | list[RequestMappingRule],
        fallback_rule: RequestMappingRule | None = None,
    ) -> None:
        if isinstance(rules, Mapping):
            self._rules = dict(rules)
        else:
            self._rules = {rule.selector: rule for rule in rules}
        self._fallback_rule = fallback_rule

    def authorization_request(
        self,
        context: object,
        identity: RequestIdentity,
    ) -> AuthorizationRequest:
        rule = self._rule_for(context)
        return AuthorizationRequest(
            identity=identity,
            operation=rule.operation,
            resource=self._resource_for(context, rule),
        )

    def candidate_resources_request(
        self,
        context: object,
        identity: RequestIdentity,
    ) -> CandidateResourcesRequest:
        rule = self._rule_for(context)
        if rule.resource_type is None:
            raise ResourceMappingError("candidate resources require a resource_type")
        return CandidateResourcesRequest(
            identity=identity,
            operation=rule.operation,
            resource_type=rule.resource_type,
        )

    def _rule_for(self, context: object) -> RequestMappingRule:
        selector = _get(context, "selector")
        if selector is None:
            raise ResourceMappingError("invocation context has no selector")
        rule = self._rules.get(str(selector))
        if rule is not None:
            return rule
        if self._fallback_rule is not None and self._fallback_rule.fallback_protected:
            return self._fallback_rule
        raise ResourceMappingError(f"unmapped request selector: {selector!r}")

    def _resource_for(self, context: object, rule: RequestMappingRule) -> ResourceRef:
        if rule.resource_type is None:
            return ResourceRef.system()
        if rule.resource_id_source is None:
            return ResourceRef.type_root(rule.resource_type)
        resource_id = _lookup_resource_id(context, rule.resource_id_source)
        if resource_id is None or str(resource_id).strip() == "":
            raise ResourceMappingError(
                f"resource id source {rule.resource_id_source!r} did not resolve"
            )
        return ResourceRef(rule.resource_type, str(resource_id))


def _get(context: object, name: str) -> object | None:
    if isinstance(context, Mapping):
        return context.get(name)
    return getattr(context, name, None)


def _lookup_resource_id(context: object, source: str) -> object | None:
    if isinstance(context, Mapping):
        resource_ids = context.get("resource_ids", {})
        attributes = context.get("attributes", {})
    else:
        resource_ids = getattr(context, "resource_ids", {})
        attributes = getattr(context, "attributes", {})
    if isinstance(resource_ids, Mapping) and source in resource_ids:
        return resource_ids[source]
    if isinstance(attributes, Mapping) and source in attributes:
        return attributes[source]
    return _get(context, source)
