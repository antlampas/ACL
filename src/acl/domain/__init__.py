# SPDX-License-Identifier: CC-BY-SA-4.0

"""Pure ACL domain objects and matching functions."""

from .decisions import Decision, EvaluationResult, JoinOp, Permission
from .entries import ACLEntry
from .errors import (
    ACLError,
    ACLValidationError,
    AuthenticationRequired,
    AuthorizationDenied,
    GrantConstraintError,
    OperationUnknownError,
    ResourceMappingError,
)
from .identifiers import (
    ACLEntryId,
    ANON_SENTINEL,
    GroupId,
    OperationName,
    PUBLIC_GROUP,
    SubjectId,
    SYSTEM_ID,
    SYSTEM_TYPE,
    TYPE_ROOT_ID,
)
from .invariants import ACLEntryInvariants
from .matching import entry_matches, profile_part_matches, resolve, subject_matches
from .operations import OperationSpec
from .profiles import Profile
from .resources import ResourceRef
from .subjects import SubjectRef, SubjectType

__all__ = [
    "ACLEntry",
    "ACLEntryId",
    "ACLEntryInvariants",
    "ACLError",
    "ACLValidationError",
    "ANON_SENTINEL",
    "AuthenticationRequired",
    "AuthorizationDenied",
    "Decision",
    "EvaluationResult",
    "GrantConstraintError",
    "GroupId",
    "JoinOp",
    "OperationName",
    "OperationSpec",
    "OperationUnknownError",
    "PUBLIC_GROUP",
    "Permission",
    "Profile",
    "ResourceMappingError",
    "ResourceRef",
    "SYSTEM_ID",
    "SYSTEM_TYPE",
    "SubjectId",
    "SubjectRef",
    "SubjectType",
    "TYPE_ROOT_ID",
    "entry_matches",
    "profile_part_matches",
    "resolve",
    "subject_matches",
]
