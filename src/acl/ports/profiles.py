# SPDX-License-Identifier: CC-BY-SA-4.0

"""Profile provider ports."""

from __future__ import annotations

from typing import Protocol

from acl.domain import Profile, SubjectRef


class ProfileProvider(Protocol):
    def profile_of(self, subject: SubjectRef) -> Profile: ...


class ProfileWriter(Protocol):
    def set_profile(self, subject: SubjectRef, profile: Profile) -> None: ...
