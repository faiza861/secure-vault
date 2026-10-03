"""Short-lived, signed, STATELESS session tokens.

WHAT A SESSION IS (and is not)
* It proves "this browser authenticated recently (passphrase, plus TOTP when MFA is on)" so that
  code-gated actions do not ask for a fresh TOTP code every single time.
* It is NOT a login that replaces the passphrase. In this stateless, serverless design the
  passphrase is still needed on every request to derive keys, so it stays in browser memory.
  The token carries NO passphrase, NO key material and NO secret; a stolen token alone
  unlocks nothing.

HOW IT WORKS WITHOUT A SERVER-SIDE STORE
* The token is `v1.<base64url JSON claims>.<base64url HMAC-SHA256>`. The HMAC key is
  SESSION_SECRET from the environment (never hardcoded, never logged). Primitives: stdlib
  `hmac`, `hashlib`, `secrets`. Signatures are compared with `hmac.compare_digest`.
* Two clocks: an ABSOLUTE expiry (`exp`) and an INACTIVITY timeout (`act` + idle). Because the
  server keeps no state, every successful request returns a refreshed token with a new `act`;
  the browser swaps it in memory.
* `ra` / `mf` record when the holder last authenticated and whether a TOTP code was verified
  then. A session counts as "recent MFA-verified authentication" only if `mf` is true and `ra`
  is inside the reauth window. A session created before MFA was enabled has mf=false, so it can
  never stand in for a code.
* Revocation (logout) is a `session_revoked` record in the audit hash chain, matched by a
  fingerprint of the session id. Pure functions here; the caller supplies the revoked set.
"""

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import asdict, dataclass

from securevault.utils.exceptions import SessionExpired, SessionInvalid

_PREFIX = "v1"
_MAX_TOKEN_CHARS = 600  # refuse absurd input before doing any parsing
_SIG_CONTEXT = b"securevault/session/v1."  # domain separation for the HMAC


@dataclass(frozen=True)
class SessionPolicy:
    ttl_seconds: int = 900
    idle_seconds: int = 300
    reauth_window_seconds: int = 300


@dataclass(frozen=True)
class SessionClaims:
    sid: str  # random 128-bit id (not a secret by itself: the signature is what authenticates)
    iat: float  # issued at
    exp: float  # absolute expiry
    act: float  # last activity
    ra: float  # last (re)authentication
    mf: bool  # a TOTP code was verified at `ra`


def policy_from_settings(settings) -> SessionPolicy:
    return SessionPolicy(settings.session_ttl_seconds, settings.session_idle_seconds, settings.reauth_window_seconds)


def sid_fingerprint(sid: str) -> str:
    """What goes into the audit log instead of the raw id."""
    return hashlib.sha256(sid.encode()).hexdigest()[:16]


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(secret: bytes, payload_b64: str) -> str:
    return _b64e(hmac.new(secret, _SIG_CONTEXT + payload_b64.encode("ascii"), hashlib.sha256).digest())


def new_claims(now: float, policy: SessionPolicy, *, mfa_verified: bool) -> SessionClaims:
    return SessionClaims(secrets.token_hex(16), now, now + policy.ttl_seconds, now, now, mfa_verified)


def encode(secret: bytes, claims: SessionClaims) -> str:
    payload = _b64e(json.dumps(asdict(claims), separators=(",", ":"), sort_keys=True).encode())
    return f"{_PREFIX}.{payload}.{_sign(secret, payload)}"


def decode(secret: bytes, token: str) -> SessionClaims:
    """Verify the signature and shape. Does NOT check expiry (see check_active). Anything wrong,
    including any unexpected error, raises SessionInvalid: fail closed."""
    try:
        if not isinstance(token, str) or len(token) > _MAX_TOKEN_CHARS:
            raise SessionInvalid("bad session")
        prefix, payload, signature = token.split(".")
        if prefix != _PREFIX or not hmac.compare_digest(_sign(secret, payload), signature):
            raise SessionInvalid("bad session")
        raw = json.loads(_b64d(payload))
        claims = SessionClaims(
            sid=str(raw["sid"]), iat=float(raw["iat"]), exp=float(raw["exp"]),
            act=float(raw["act"]), ra=float(raw["ra"]), mf=raw["mf"] is True,
        )
        if len(claims.sid) != 32:
            raise SessionInvalid("bad session")
        return claims
    except SessionInvalid:
        raise
    except Exception:  # noqa: BLE001 - malformed token of any kind is simply invalid
        raise SessionInvalid("bad session") from None


def check_active(claims: SessionClaims, now: float, policy: SessionPolicy) -> None:
    """Raise SessionExpired if the absolute lifetime or the inactivity timeout has passed."""
    if now >= claims.exp:
        raise SessionExpired("absolute")
    if now - claims.act >= policy.idle_seconds:
        raise SessionExpired("idle")
    if claims.iat > now + 5:  # issued "in the future": clock trouble or tampering
        raise SessionInvalid("bad session")


def is_recent_mfa(claims: SessionClaims, now: float, policy: SessionPolicy) -> bool:
    """True when this session can stand in for a TOTP code right now."""
    return claims.mf and 0 <= now - claims.ra <= policy.reauth_window_seconds


def touch(claims: SessionClaims, now: float, *, reauthenticated: bool = False, mfa_verified: bool = False) -> SessionClaims:
    """Refreshed claims for the next token: new activity time; new auth time if the request re-proved
    identity. `mf` only ever becomes true by verifying a code (it is never inherited upward)."""
    if reauthenticated:
        return SessionClaims(claims.sid, claims.iat, claims.exp, now, now, mfa_verified)
    return SessionClaims(claims.sid, claims.iat, claims.exp, now, claims.ra, claims.mf)


_process_secret: bytes | None = None


def secret_from_settings(settings, warn=None) -> bytes:
    """SESSION_SECRET if it is long enough, otherwise a random per-process secret (memory only)."""
    global _process_secret
    configured = (settings.session_secret or "").strip()
    if len(configured) >= 32:
        return configured.encode("utf-8")
    if _process_secret is None:
        _process_secret = secrets.token_bytes(32)
        if warn:
            warn("SESSION_SECRET is not set (or shorter than 32 characters): using a random per-process "
                 "secret. Sessions will not survive a restart or span several serverless instances.")
    return _process_secret
