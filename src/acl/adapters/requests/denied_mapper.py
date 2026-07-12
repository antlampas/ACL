# SPDX-License-Identifier: CC-BY-SA-4.0

"""Simple protocol-neutral denied/error mapper."""

from __future__ import annotations

from acl.domain import (
    ACLError,
    ACLValidationError,
    AuthenticationRequired,
    AuthorizationDenied,
    GrantConstraintError,
    OperationUnknownError,
    ResourceMappingError,
)


class DictDeniedResponseMapper:
    def map_error(self, error: ACLError, context: object | None = None) -> dict[str, object]:
        status = 500
        code = "acl_error"
        if isinstance(error, AuthenticationRequired):
            status = 401
            code = "authentication_required"
        elif isinstance(error, AuthorizationDenied):
            status = 403
            code = "authorization_denied"
        elif isinstance(error, (ACLValidationError, GrantConstraintError)):
            status = 400
            code = "acl_validation_error"
        elif isinstance(error, OperationUnknownError):
            status = 400
            code = "operation_unknown"
        elif isinstance(error, ResourceMappingError):
            status = 400
            code = "resource_mapping_error"
        return {"ok": False, "status": status, "code": code, "message": str(error)}
