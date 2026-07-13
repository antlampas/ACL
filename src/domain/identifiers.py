# SPDX-License-Identifier: CC-BY-SA-4.0

"""Domain identifiers and reserved ACL constants."""

from typing import NewType

ACLEntryId = NewType("ACLEntryId", str)
SubjectId = NewType("SubjectId", str)
GroupId = NewType("GroupId", str)
OperationName = NewType("OperationName", str)

SYSTEM_TYPE = "SYSTEM"
SYSTEM_ID = "global"
TYPE_ROOT_ID = "*"
PUBLIC_GROUP = "public"
ANON_SENTINEL = 2**31 - 1
