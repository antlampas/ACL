# SPDX-License-Identifier: CC-BY-SA-4.0

"""Permissions declared by entries and decisions returned by the policy."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Permission(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class JoinOp(StrEnum):
    AND = "AND"
    OR = "OR"


class Decision(StrEnum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    decision: Decision
    explicit_deny: bool = False
