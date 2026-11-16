"""Replay detector for token/session usage sequences.

Given a sequence describing how a token (or session id) is used over time,
classify each use as either legitimate or an attack, and state the evidence.

The detector models the three lifecycle flaws that make a token replayable:

1. use-after-consume  -> REPLAY          (red test: test_replay_is_rejected)
2. use-after-expiry   -> EXPIRED         (red test: test_expired_session_rejected)
3. id reuse across a
   privilege boundary -> SESSION_FIXATION (red test: test_session_id_rotates_after_mfa)

The fourth red test, test_compare_is_constant_time, is a timing-side-channel
issue rather than a sequence property; it is fixed in SessionStore and has no
sequence-level verdict here.

Legitimate sequences -- first use inside the TTL, different codes at each
step, and a fresh id after the MFA boundary -- never produce a verdict other
than OK, so there are no false positives on valid traffic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hmac

from auth.totp import hotp


class Verdict(str, Enum):
    OK = "ok"
    REPLAY = "replay"
    EXPIRED = "expired"
    SESSION_FIXATION = "session_fixation"


@dataclass(frozen=True)
class UsageEvent:
    """One observed use of a token.

    token_id  identifier presented to the service (reset token / session id).
    at        unix timestamp of the use.
    code      secret material carried by the token, e.g. the TOTP digits;
              two events carrying the same code are the same credential.
    issued_at when the token was minted; defaults to its first appearance.
    """

    token_id: str
    at: int
    code: str | None = None
    issued_at: int | None = None


@dataclass(frozen=True)
class EventVerdict:
    index: int
    event: UsageEvent
    verdict: Verdict
    reason: str


@dataclass
class TokenLifecycleDetector:
    """Stateful detector fed an ordered usage sequence."""

    ttl_seconds: int = 3600
    _first_seen: dict[str, int] = field(default_factory=dict)
    _consumed_codes: set[tuple[str, str]] = field(default_factory=set)
    _pre_boundary_ids: set[str] = field(default_factory=set)

    def inspect(
        self,
        events: list[UsageEvent],
        privilege_boundary_after: int | None = None,
    ) -> list[EventVerdict]:
        """Inspect a full sequence.

        privilege_boundary_after is the index of the event that completes MFA
        (or any equivalent step that raises the session's privilege level).
        An id already seen before that index and presented again afterwards
        is a session-fixation attempt.
        """
        results: list[EventVerdict] = []
        self._pre_boundary_ids.clear()

        for i, event in enumerate(events):
            if privilege_boundary_after is not None and i <= privilege_boundary_after:
                self._pre_boundary_ids.add(event.token_id)

            issued = event.issued_at
            if issued is None:
                issued = self._first_seen.setdefault(event.token_id, event.at)

            # Rule 2: token outlived its validity window.
            if event.at - issued >= self.ttl_seconds:
                results.append(
                    EventVerdict(
                        i,
                        event,
                        Verdict.EXPIRED,
                        f"age {event.at - issued}s >= TTL {self.ttl_seconds}s; "
                        "an expired token must never be accepted",
                    )
                )
                continue

            # Rule 3: same id crosses the MFA/privilege boundary.
            if (
                privilege_boundary_after is not None
                and i > privilege_boundary_after
                and event.token_id in self._pre_boundary_ids
            ):
                results.append(
                    EventVerdict(
                        i,
                        event,
                        Verdict.SESSION_FIXATION,
                        "token id was already in use before the privilege "
                        "boundary and was not rotated; a fixated id survives "
                        "the victim authenticating",
                    )
                )
                continue

            # Rule 1: credential material already consumed.
            if event.code is not None:
                key = (event.token_id, event.code)
                if key in self._consumed_codes:
                    results.append(
                        EventVerdict(
                            i,
                            event,
                            Verdict.REPLAY,
                            f"code {event.code!r} was already presented and "
                            "consumed; single-use tokens must be invalidated "
                            "on first successful use",
                        )
                    )
                    continue
                self._consumed_codes.add(key)

            results.append(
                EventVerdict(i, event, Verdict.OK, "first in-window presentation")
            )

        return results


@dataclass(frozen=True)
class TotpUsage:
    """One use of a TOTP code: the presented digits and the time of use."""

    code: str
    at: int


def analyze_totp_sequence(
    secret: bytes,
    usages: list[TotpUsage | tuple[str, int]],
    step: int = 30,
) -> list[EventVerdict]:
    """Specialised replay analysis for a TOTP usage sequence.

    Mirrors auth.totp.verify: acceptance window is counters (C-1, C), and a
    counter may be consumed at most once. Each usage is judged against the
    code's own step, so distinct legitimate codes at distinct steps are all
    OK while a repeated digit is flagged REPLAY.
    """
    consumed_counters: set[int] = set()
    results: list[EventVerdict] = []

    for i, usage in enumerate(usages):
        if isinstance(usage, TotpUsage):
            code, at = usage.code, usage.at
        else:
            code, at = usage
        current = at // step
        event = UsageEvent(token_id=secret.hex() or "totp", at=at, code=code)

        matched = next(
            (
                counter
                for counter in (current - 1, current)
                if hmac.compare_digest(hotp(secret, counter), code)
            ),
            None,
        )

        if matched is None:
            results.append(
                EventVerdict(
                    i,
                    event,
                    Verdict.EXPIRED,
                    f"code {code!r} matches neither step {current - 1} nor "
                    f"{current}; it is outside the acceptance window",
                )
            )
        elif matched in consumed_counters:
            results.append(
                EventVerdict(
                    i,
                    event,
                    Verdict.REPLAY,
                    f"code {code!r} belongs to step {matched}, which was "
                    "already consumed; TOTP codes are single-use",
                )
            )
        else:
            consumed_counters.add(matched)
            results.append(
                EventVerdict(
                    i,
                    event,
                    Verdict.OK,
                    f"code {code!r} matches step {matched}, first use",
                )
            )

    return results
