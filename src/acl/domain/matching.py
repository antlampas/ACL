# SPDX-License-Identifier: CC-BY-SA-4.0

"""Pure matching and deny-override resolution functions."""

from __future__ import annotations

from collections.abc import Sequence

from .decisions import Decision, EvaluationResult, JoinOp, Permission
from .entries import ACLEntry
from .profiles import Profile
from .subjects import SubjectRef, SubjectType


def subject_matches(entry_subject: SubjectRef, subject: SubjectRef) -> bool:
    if entry_subject.type == SubjectType.PUBLIC:
        return True
    return entry_subject == subject


def profile_part_matches(entry: ACLEntry, profile: Profile) -> bool:
    parts: list[bool] = []
    if entry.level is not None:
        parts.append(profile.level <= entry.level)
    if entry.group is not None:
        parts.append(entry.group in profile.groups)
    if not parts:
        return False
    return all(parts) if entry.profile_join == JoinOp.AND else any(parts)


def entry_matches(entry: ACLEntry, subject: SubjectRef, profile: Profile) -> bool:
    subject_part = subject_matches(entry.subject, subject)
    profile_part = profile_part_matches(entry, profile)
    if entry.subject_join == JoinOp.AND:
        return subject_part and profile_part
    return subject_part or profile_part


def resolve(
    entries: Sequence[ACLEntry],
    subject: SubjectRef,
    profile: Profile,
) -> EvaluationResult:
    matching = [entry for entry in entries if entry_matches(entry, subject, profile)]
    if any(entry.permission == Permission.DENY for entry in matching):
        return EvaluationResult(Decision.DENIED, explicit_deny=True)
    if any(entry.permission == Permission.ALLOW for entry in matching):
        return EvaluationResult(Decision.ALLOWED)
    return EvaluationResult(Decision.DENIED)
