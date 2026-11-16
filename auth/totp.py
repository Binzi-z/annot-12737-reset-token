"""Minimal TOTP implementation used by the SSO service."""

from __future__ import annotations

import hashlib
import hmac
import struct
import time


def hotp(secret: bytes, counter: int, digits: int = 6) -> str:
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp(secret: bytes, at: int | None = None, step: int = 30, digits: int = 6) -> str:
    return hotp(secret, int((at or time.time()) // step), digits)


# Remembers the most recently consumed HOTP counter per secret.
#
# The acceptance window only ever contains counters (C-1, C): any older code
# is cryptographically rejected regardless of this memory, so the only codes
# that can possibly be replayed are those two counters. Recording the last
# consumed one turns a second presentation of the same code into a rejection.
_last_consumed: dict[bytes, int] = {}


def verify(secret: bytes, code: str, at: int | None = None, step: int = 30) -> bool:
    """Check a code against the current step and the previous one.

    A successfully consumed counter is remembered; presenting the same code
    again while it is still inside the acceptance window is rejected as a
    replay. Comparison is constant-time so response timing cannot leak how
    many leading digits matched.
    """
    now = int((at or time.time()) // step)
    last_consumed = _last_consumed.get(secret)
    for counter in (now - 1, now):
        if hmac.compare_digest(hotp(secret, counter), code):
            if counter == last_consumed:
                return False
            _last_consumed[secret] = counter
            return True
    return False
