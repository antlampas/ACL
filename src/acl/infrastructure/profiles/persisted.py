# SPDX-License-Identifier: CC-BY-SA-4.0

"""In-memory authoritative profile store for tests and small integrations."""

from __future__ import annotations

from threading import RLock

from acl.domain import Profile, SubjectRef, SubjectType


class InMemoryProfileProvider:
    def __init__(self, profiles: dict[SubjectRef, Profile] | None = None) -> None:
        self._profiles = dict(profiles or {})
        self._lock = RLock()

    def profile_of(self, subject: SubjectRef) -> Profile:
        if subject.type == SubjectType.PUBLIC:
            return Profile.anonymous()
        with self._lock:
            return self._profiles.get(subject, Profile.anonymous())

    def set_profile(self, subject: SubjectRef, profile: Profile) -> None:
        if subject.type == SubjectType.PUBLIC:
            raise ValueError("PUBLIC cannot have a persisted profile")
        with self._lock:
            self._profiles[subject] = profile

    def delete_profile(self, subject: SubjectRef) -> None:
        with self._lock:
            self._profiles.pop(subject, None)
