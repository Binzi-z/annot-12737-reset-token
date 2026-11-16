"""Tests for the usage-sequence replay detector.

The cases map one-to-one onto the red security tests in test_auth.py:

    test_detector_flags_replay          <-> test_replay_is_rejected
    test_detector_flags_expired         <-> test_expired_session_rejected
    test_detector_flags_fixation        <-> test_session_id_rotates_after_mfa

(The fourth red test, test_compare_is_constant_time, is a timing side channel
with no sequence-level representation.) Every legitimate sequence below must
come back with zero non-OK verdicts.
"""

from auth.replay_detector import (
    TokenLifecycleDetector,
    TotpUsage,
    UsageEvent,
    Verdict,
    analyze_totp_sequence,
)
from auth.totp import totp

SECRET = b"12345678901234567890"
TTL = 3600


def _names(results):
    return [r.verdict for r in results]


# ---- red case 1: use-after-consume (replay) ------------------------------


def test_detector_flags_replay():
    now = 1_700_000_000
    code = totp(SECRET, at=now)
    events = [
        UsageEvent("reset-token-1", now, code=code),
        UsageEvent("reset-token-1", now + 5, code=code),
    ]
    results = TokenLifecycleDetector(ttl_seconds=TTL).inspect(events)
    assert _names(results) == [Verdict.OK, Verdict.REPLAY]
    assert "already presented" in results[1].reason


def test_detector_totp_sequence_matches_replay_red_case():
    # Same sequence as test_replay_is_rejected: identical code, same step.
    now = 1_700_000_000
    code = totp(SECRET, at=now)
    results = analyze_totp_sequence(SECRET, [TotpUsage(code, now), TotpUsage(code, now)])
    assert _names(results) == [Verdict.OK, Verdict.REPLAY]


# ---- red case 2: use-after-expiry ----------------------------------------


def test_detector_flags_expired():
    # Same shape as test_expired_session_rejected: issued at 1000, used 7200s
    # later with a 3600s TTL.
    events = [UsageEvent("sid", 1000 + 7200, code="x", issued_at=1000)]
    results = TokenLifecycleDetector(ttl_seconds=TTL).inspect(events)
    assert _names(results) == [Verdict.EXPIRED]
    assert "TTL" in results[0].reason


def test_detector_totp_sequence_flags_out_of_window_code():
    now = 1_700_000_000
    stale = totp(SECRET, at=now - 300)  # ten steps old, outside (C-1, C)
    results = analyze_totp_sequence(SECRET, [TotpUsage(stale, now)])
    assert _names(results) == [Verdict.EXPIRED]


# ---- red case 3: session fixation across the MFA boundary ----------------


def test_detector_flags_fixation():
    events = [
        UsageEvent("fixated-sid", 100, code="pre-mfa"),
        UsageEvent("fixated-sid", 200, code="post-mfa"),
    ]
    results = TokenLifecycleDetector(ttl_seconds=TTL).inspect(
        events, privilege_boundary_after=0
    )
    assert _names(results) == [Verdict.OK, Verdict.SESSION_FIXATION]


def test_detector_accepts_rotated_id_after_boundary():
    events = [
        UsageEvent("old-sid", 100, code="pre-mfa"),
        UsageEvent("new-sid", 200, code="post-mfa"),
    ]
    results = TokenLifecycleDetector(ttl_seconds=TTL).inspect(
        events, privilege_boundary_after=0
    )
    assert _names(results) == [Verdict.OK, Verdict.OK]


# ---- zero false positives on legitimate traffic --------------------------


def test_legitimate_distinct_codes_each_step_are_all_ok():
    now = 1_700_000_000
    usages = [
        TotpUsage(totp(SECRET, at=now), now),
        TotpUsage(totp(SECRET, at=now + 30), now + 30),
        TotpUsage(totp(SECRET, at=now + 60), now + 60),
    ]
    results = analyze_totp_sequence(SECRET, usages)
    assert all(r.verdict is Verdict.OK for r in results)


def test_legitimate_previous_step_code_is_ok():
    # Mirrors test_verify_accepts_previous_step: one-step-old, first use.
    now = 1_700_000_000
    previous = totp(SECRET, at=now - 30)
    results = analyze_totp_sequence(SECRET, [TotpUsage(previous, now)])
    assert _names(results) == [Verdict.OK]


def test_legitimate_sequence_inside_ttl_with_unique_tokens_is_all_ok():
    events = [
        UsageEvent("t1", 100, code="c1"),
        UsageEvent("t2", 1000, code="c2"),
        UsageEvent("t3", 3500, code="c3"),
    ]
    results = TokenLifecycleDetector(ttl_seconds=TTL).inspect(events)
    assert all(r.verdict is Verdict.OK for r in results)


def test_legitimate_boundary_at_exact_ttl_is_expired_not_ok():
    # age == TTL must count as expired (>= comparison), same as SessionStore.
    events = [UsageEvent("t", TTL, code="c", issued_at=0)]
    results = TokenLifecycleDetector(ttl_seconds=TTL).inspect(events)
    assert _names(results) == [Verdict.EXPIRED]
