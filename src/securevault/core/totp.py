"""TOTP (RFC 6238) on the standard library only: hmac, hashlib, struct, base64, secrets, time.

This is HOTP (RFC 4226) with the counter taken from the clock. Nothing here is a hand-written
cryptographic primitive: HMAC-SHA1 comes from `hmac`/`hashlib`, randomness from `secrets`,
and codes are compared with `hmac.compare_digest`.

Parameters are fixed to what common authenticator apps expect: HMAC-SHA1, 6 digits, 30 s step,
160-bit secret. Honest limit: TOTP is NOT phishing-resistant. A fake login page can relay a
valid code in real time. It raises the cost of online password guessing; it does not stop that.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

DIGITS = 6
STEP_SECONDS = 30
SECRET_BYTES = 20  # 160 bits, the size RFC 4226 recommends
DEFAULT_WINDOW = 1  # accept the current step +/- 1 to tolerate clock drift


def generate_secret() -> str:
    """New random secret, Base32 without padding (what authenticator apps expect)."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    cleaned = secret.strip().replace(" ", "").upper()
    return base64.b32decode(cleaned + "=" * (-len(cleaned) % 8), casefold=False)


def is_valid_secret(secret: str) -> bool:
    """True only for a Base32 string that decodes to exactly the 160-bit size we issue."""
    try:
        return isinstance(secret, str) and len(_decode_secret(secret)) == SECRET_BYTES
    except ValueError:  # binascii.Error is a ValueError
        return False


def hotp(key: bytes, counter: int, digits: int = DIGITS) -> str:
    """RFC 4226 HOTP: HMAC-SHA1 over the 8-byte big-endian counter, dynamic truncation."""
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10**digits)).zfill(digits)


def time_step(now: float | None = None, step: int = STEP_SECONDS) -> int:
    return int((time.time() if now is None else now) // step)


def totp(secret: str, now: float | None = None, step: int = STEP_SECONDS, digits: int = DIGITS) -> str:
    """The code that is valid at `now` (used by tests and by the self-check at enrollment)."""
    return hotp(_decode_secret(secret), time_step(now, step), digits)


def verify(secret: str, code: str, now: float | None = None, window: int = DEFAULT_WINDOW) -> int | None:
    """Return the matched time step, or None. Wrong length / non-digits are rejected up front.

    The caller needs the step for replay protection (a step must never be accepted twice).
    All candidate steps are always compared, so timing does not reveal which one matched.
    """
    if not isinstance(code, str) or len(code) != DIGITS or not (code.isascii() and code.isdigit()):
        return None
    key = _decode_secret(secret)
    current = time_step(now)
    matched: int | None = None
    for step in range(current - window, current + window + 1):
        if step >= 0 and hmac.compare_digest(hotp(key, step), code):
            matched = step
    return matched


def provisioning_uri(secret: str, account: str, issuer: str = "Secure Vault") -> str:
    """otpauth:// URI that authenticator apps read from a QR code."""
    label = f"{quote(issuer, safe='')}:{quote(account, safe='')}"
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer, safe='')}"
        f"&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
    )
