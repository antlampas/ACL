# SPDX-License-Identifier: CC-BY-SA-4.0

"""ACL error hierarchy shared by application services and adapters."""

from dataclasses import dataclass


class ACLError(Exception):
    """Base class for ACL package errors."""


class AuthenticationRequired(ACLError):
    """Raised when a boundary requires an authenticated identity."""


@dataclass(slots=True)
class AuthorizationDenied(ACLError):
    """Raised when a normalized request is not authorized."""

    message: str = "authorization denied"
    trace: object | None = None

    def __str__(self) -> str:
        return self.message


class ACLValidationError(ACLError, ValueError):
    """Raised when an ACL entry or DTO violates ACL invariants."""


class GrantConstraintError(ACLError):
    """Raised when a grant is forbidden by grant constraints."""


class OperationUnknownError(ACLError, LookupError):
    """Raised when an operation is not present in the catalog."""


class ResourceMappingError(ACLError, LookupError):
    """Raised when a request cannot be mapped to a resource safely."""
