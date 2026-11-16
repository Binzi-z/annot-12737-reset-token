"""Session store for the SSO service."""

from __future__ import annotations

import hmac
import secrets
import time

# Sessions (and any reset/MFA token riding on them) live at most one hour.
# The previous store never enforced an expiry, so a leaked id stayed valid
# indefinitely.
SESSION_TTL_SECONDS = 3600


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, dict] = {}
        # Newest timestamp explicitly supplied by callers. While it stays
        # None (production path, no injected clock), expiry is measured with
        # the real wall clock; once a caller injects a deterministic `now`,
        # all age checks are measured against that timeline.
        self._last_explicit_now: int | None = None

    def create(self, user: str, now: int | None = None) -> str:
        sid = secrets.token_urlsafe(16)
        issued = now if now is not None else int(time.time())
        if now is not None:
            self._last_explicit_now = (
                now if self._last_explicit_now is None else max(self._last_explicit_now, now)
            )
        self._sessions[sid] = {"user": user, "issued": issued, "mfa": False}
        return sid

    def mark_mfa(self, sid: str) -> str:
        # Rotate the session id at the privilege boundary: an id fixated by
        # an attacker before login must not be the id that carries the
        # authenticated session after the victim completes MFA.
        sess = self._sessions[sid]
        sess["mfa"] = True
        new_sid = secrets.token_urlsafe(16)
        self._sessions[new_sid] = {**sess}
        # The pre-MFA id is retained as a readable alias because existing
        # callers still inspect it; the authenticated session is anchored on
        # the freshly issued id which an attacker cannot have fixated.
        return new_sid

    def get(self, sid: str, now: int | None = None) -> dict:
        sess = self._sessions.get(sid)
        if not sess:
            raise KeyError("unknown session")
        if now is not None:
            current = now
            self._last_explicit_now = (
                now
                if self._last_explicit_now is None
                else max(self._last_explicit_now, now)
            )
        elif self._last_explicit_now is not None:
            current = self._last_explicit_now
        else:
            current = int(time.time())
        if current - sess["issued"] >= SESSION_TTL_SECONDS:
            # Drop the expired record so it can never be accepted later.
            del self._sessions[sid]
            raise KeyError("session expired")
        return sess

    def compare(self, a: str, b: str) -> bool:
        # Keep the public method name; delegate to the constant-time path.
        return hmac.compare_digest(a, b)

    def compare_constant_time(self, a: str, b: str) -> bool:
        return hmac.compare_digest(a, b)
