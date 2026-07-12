# SPDX-License-Identifier: CC-BY-SA-4.0

"""Pure ACL authorization policy with inheritance and trace support."""

from __future__ import annotations

from dataclasses import dataclass

from acl.application.dto import DecisionTrace
from acl.domain import (
    ACLEntryId,
    Decision,
    EvaluationResult,
    Permission,
    Profile,
    ResourceRef,
    SubjectRef,
    entry_matches,
    resolve,
)
from acl.ports import (
    ACLEntryRepository,
    OperationCatalog,
    ProfileProvider,
    ResourceHierarchyProvider,
)


@dataclass(frozen=True, slots=True)
class _EvalTrace:
    result: EvaluationResult
    reason: str
    matched_entry_ids: tuple[ACLEntryId, ...] = ()


class AuthorizationPolicy:
    def __init__(
        self,
        entries: ACLEntryRepository,
        profiles: ProfileProvider,
        hierarchy: ResourceHierarchyProvider,
        operations: OperationCatalog,
    ) -> None:
        self._entries = entries
        self._profiles = profiles
        self._hierarchy = hierarchy
        self._operations = operations

    def is_allowed(
        self,
        subject: SubjectRef,
        operation: str,
        resource: ResourceRef,
    ) -> Decision:
        return self.explain(subject, operation, resource).decision

    def candidate_resources(
        self,
        subject: SubjectRef,
        operation: str,
        resource_type: str,
    ) -> list[ResourceRef]:
        spec = self._operations.require(operation)
        profile = self._profiles.profile_of(subject)
        candidates: set[ResourceRef] = set()
        for entry in self._entries.list_by_operation(spec.name, resource_type.strip().upper()):
            if entry.permission == Permission.ALLOW and entry_matches(entry, subject, profile):
                candidates.add(entry.resource)
        return sorted(candidates)

    def explain(
        self,
        subject: SubjectRef,
        operation: str,
        resource: ResourceRef,
    ) -> DecisionTrace:
        spec = self._operations.require(operation)
        profile = self._profiles.profile_of(subject)
        visited_order: list[ResourceRef] = []
        memo: dict[ResourceRef, _EvalTrace] = {}
        in_progress: set[ResourceRef] = set()

        def evaluate(current: ResourceRef, path: frozenset[ResourceRef]) -> _EvalTrace:
            if current in path or current in in_progress:
                return _EvalTrace(EvaluationResult(Decision.DENIED), "cycle_detected")
            if current in memo:
                return memo[current]

            visited_order.append(current)
            in_progress.add(current)
            try:
                own = self._entries.entries_for(current, spec.name)
                if own:
                    result = resolve(own, subject, profile)
                    matched_ids = tuple(
                        entry.id for entry in own if entry_matches(entry, subject, profile)
                    )
                    if result.explicit_deny:
                        reason = "own_explicit_deny"
                    elif result.decision == Decision.ALLOWED:
                        reason = "own_allow"
                    else:
                        reason = "own_default_deny"
                    trace = _EvalTrace(result, reason, matched_ids)
                    memo[current] = trace
                    return trace

                if not spec.inheritable:
                    trace = _EvalTrace(EvaluationResult(Decision.DENIED), "operation_not_inheritable")
                    memo[current] = trace
                    return trace

                parent_traces = [
                    evaluate(parent, path | {current})
                    for parent in self._hierarchy.parents_of(current)
                ]
                matched_ids = tuple(
                    entry_id
                    for parent_trace in parent_traces
                    for entry_id in parent_trace.matched_entry_ids
                )
                if any(parent_trace.result.explicit_deny for parent_trace in parent_traces):
                    trace = _EvalTrace(
                        EvaluationResult(Decision.DENIED, explicit_deny=True),
                        "parent_explicit_deny",
                        matched_ids,
                    )
                elif any(parent_trace.result.decision == Decision.ALLOWED for parent_trace in parent_traces):
                    trace = _EvalTrace(EvaluationResult(Decision.ALLOWED), "parent_allow", matched_ids)
                else:
                    trace = _EvalTrace(EvaluationResult(Decision.DENIED), "default_deny", matched_ids)
                memo[current] = trace
                return trace
            finally:
                in_progress.discard(current)

        trace = evaluate(resource, frozenset())
        return DecisionTrace(
            subject=subject,
            profile=profile,
            operation=spec.name,
            resource=resource,
            decision=trace.result.decision,
            reason=trace.reason,
            explicit_deny=trace.result.explicit_deny,
            matched_entry_ids=trace.matched_entry_ids,
            visited_resources=tuple(dict.fromkeys(visited_order)),
        )
