"""Request authentication policy: lockout -> passphrase -> (MFA code or recent MFA session) -> action.

Kept out of main.py so the policy is in one reviewable place. Everything here FAILS CLOSED: any
unexpected error while checking a session or MFA ends in a denial, never in an allow.
"""

from dataclasses import dataclass

from fastapi import Request

from securevault.config import Settings
from securevault.security import session as sess
from securevault.storage.vault import Vault
from securevault.utils.exceptions import MfaRequired, SessionExpired, SessionInvalid
from securevault.utils.logger import get_logger

log = get_logger("securevault.api.auth")


@dataclass
class AuthResult:
    vault: Vault
    claims: sess.SessionClaims | None  # the session presented with this request, if any
    mfa_verified_now: bool = False  # a code was verified during THIS request


def bearer_token(request: Request) -> str | None:
    """Session token from `Authorization: Bearer ...`. Never read from the URL or a cookie."""
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    return value.strip() if scheme.lower() == "bearer" and value.strip() else None


def _secret(settings: Settings) -> bytes:
    return sess.secret_from_settings(settings, warn=log.warning)


def load_session(vault: Vault, token: str, settings: Settings) -> sess.SessionClaims:
    """Validate a token completely: signature, absolute expiry, inactivity, and revocation.

    Raises SessionInvalid or SessionExpired (both HTTP 401). An expired session is written to the
    audit log once (deduplicated). Any unexpected error is reported as an invalid session.
    """
    try:
        policy = sess.policy_from_settings(settings)
        claims = sess.decode(_secret(settings), token)
        now = vault.clock()
        fp = sess.sid_fingerprint(claims.sid)
        recent = vault.audit_since(claims.iat)  # revocations can only be newer than the token
        if any(e["event"] == "session_revoked" and e["details"].get("sid") == fp for e in recent):
            raise SessionInvalid("session revoked")
        try:
            sess.check_active(claims, now, policy)
        except SessionExpired as exc:
            if not any(e["event"] == "session_expired" and e["details"].get("sid") == fp for e in recent):
                vault.record_event("session_expired", {"sid": fp, "reason": exc.reason})
            raise
        return claims
    except (SessionInvalid, SessionExpired):
        raise
    except Exception:  # noqa: BLE001 - fail closed: a broken check is a denied session
        raise SessionInvalid("bad session") from None


def authenticate(
    vault: Vault,
    request: Request,
    settings: Settings,
    passphrase: str,
    totp_code: str | None = None,
    *,
    sensitive: bool,
    use_session: bool = True,
    require_code: bool = False,
) -> AuthResult:
    """Run the check order. Returns the unlocked vault.

    1. lockout check, then Argon2id passphrase unlock (both inside Vault.unlock). A wrong passphrase
       always gives the normal wrong-passphrase error: MFA state is never revealed before this passes.
    2. a session token, if one was sent, must be valid (else 401 session_invalid / session_expired).
    3. if MFA is on and the action is `sensitive`: a valid TOTP code, OR a session whose last
       MFA-verified authentication is inside the reauth window. `require_code` insists on a code.
    """
    vault.unlock(passphrase)
    token = bearer_token(request) if use_session else None
    claims = load_session(vault, token, settings) if token else None
    verified_now = False
    if vault.mfa_required and (sensitive or require_code):
        policy = sess.policy_from_settings(settings)
        if totp_code:
            vault.verify_mfa(totp_code)  # InvalidMfaCode on failure; counts toward the lockout
            verified_now = True
        elif claims is not None and not require_code and sess.is_recent_mfa(claims, vault.clock(), policy):
            pass  # recent MFA-verified authentication stands in for a code
        else:
            raise MfaRequired("authenticator code required")
    return AuthResult(vault, claims, verified_now)


def refresh_token(auth: AuthResult, settings: Settings) -> str | None:
    """Token to hand back after a successful request, so inactivity is measured from the last use.
    The auth time only moves forward when this request really re-proved identity: always when MFA is
    off (the passphrase was just checked), and only after a verified code when MFA is on."""
    if auth.claims is None:
        return None
    reauthed = auth.mfa_verified_now or not auth.vault.mfa_required
    claims = sess.touch(auth.claims, auth.vault.clock(), reauthenticated=reauthed, mfa_verified=auth.mfa_verified_now)
    return sess.encode(_secret(settings), claims)
