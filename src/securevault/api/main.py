"""HTTP API + web UI host (FastAPI).

HOSTED-MODE WARNING: in this API the server performs the decryption, so it briefly sees
the passphrase and plaintext while handling a request. That is fine for a demo you run
yourself over HTTPS, but it is NOT zero-knowledge. The CLI is the fully local mode.

Authentication order for every protected request (see api/auth.py):
    lockout check -> passphrase (Argon2id) -> if MFA is on and the action is sensitive:
    TOTP code OR a recent MFA-verified session -> action.
"""

import contextlib
import time
from collections.abc import Callable
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from securevault.api.auth import AuthResult, authenticate, bearer_token, load_session, refresh_token
from securevault.api.schemas import (
    FileOut,
    InitRequest,
    MfaConfirmRequest,
    MfaDisableRequest,
    PassphraseRequest,
    RotatePassphraseRequest,
    SessionRequest,
)
from securevault.audit import chain
from securevault.config import ROOT, get_settings
from securevault.security import session as sess
from securevault.security.lockout import check_lockout, failures_in_window, policy_from_settings
from securevault.storage import make_backend
from securevault.storage.vault import FileInfo, Vault
from securevault.utils.exceptions import (
    FileNotFound,
    IntegrityError,
    InvalidMfaCode,
    InvalidPassphrase,
    MfaAlreadyEnabled,
    MfaRequired,
    RateLimited,
    SecureVaultError,
    SessionExpired,
    SessionInvalid,
    UploadTooLarge,
    VaultAlreadyInitialized,
    VaultLocked,
    VaultNotInitialized,
    WeakPassphrase,
)
from securevault.utils.logger import get_logger

WEB_DIR = ROOT / "web"
log = get_logger("securevault.api")

_STATUS = {
    InvalidPassphrase: (401, "Wrong passphrase."),
    VaultLocked: (401, "Passphrase required."),
    MfaRequired: (401, "A current authenticator code is required."),
    InvalidMfaCode: (401, "Invalid authenticator code."),
    SessionExpired: (401, "Session expired. Sign in again."),
    SessionInvalid: (401, "Session not valid. Sign in again."),
    MfaAlreadyEnabled: (409, "MFA is already enabled."),
    FileNotFound: (404, "File not found."),
    VaultNotInitialized: (409, "No vault yet. Create one first."),
    VaultAlreadyInitialized: (409, "A vault already exists."),
    WeakPassphrase: (422, None),
    UploadTooLarge: (413, None),
    IntegrityError: (422, "Integrity check failed: stored data was modified or is corrupt."),
}


def _info(f: FileInfo) -> dict:
    return FileOut(file_id=f.file_id, size=f.size, created_ts=f.created_ts,
                   key_version=f.key_version, name=f.name).model_dump()


def _qr_data_uri(uri: str) -> str | None:
    """QR code as an SVG data: URI (allowed by the CSP's img-src). None if `segno` is unavailable,
    in which case the UI falls back to the manual key and the otpauth:// link."""
    try:
        import segno
    except ImportError:
        return None
    return segno.make(uri, error="m").svg_data_uri(scale=5, border=2, dark="#000000", light="#ffffff")


def create_app(clock: Callable[[], float] | None = None) -> FastAPI:
    app = FastAPI(title="Secure Vault", version="0.1.0", docs_url="/docs", redoc_url=None)
    now_fn = clock or time.time

    def actor_for(request: Request) -> str:
        # SECURITY: the socket address, never X-Forwarded-For (a client can forge that header to
        # dodge the per-actor limit). Behind a proxy every client shares one actor; the global
        # backstop in security/lockout.py is what still protects the vault in that case.
        host = request.client.host if request.client else "unknown"
        return f"api:{host}"[:60]

    def vault_for(request: Request) -> Vault:
        return Vault(make_backend(), actor=actor_for(request), clock=now_fn)

    def auth(request: Request, passphrase: str, totp_code: str | None = None, **kw):
        result = authenticate(vault_for(request), request, get_settings(), passphrase, totp_code, **kw)
        request.state.auth = result  # lets the middleware attach a refreshed session token
        return result

    @app.exception_handler(SecureVaultError)
    async def vault_error(_: Request, exc: SecureVaultError):
        if isinstance(exc, RateLimited):
            # 429 + Retry-After. The body repeats the delay so the UI can show a live countdown.
            return JSONResponse(
                {"error": str(exc), "code": exc.code, "retry_after": exc.retry_after},
                status_code=429, headers={"Retry-After": str(exc.retry_after)},
            )
        for cls, (code, message) in _STATUS.items():
            if isinstance(exc, cls):
                body = {"error": message or str(exc)}
                if getattr(exc, "code", None):  # machine-readable, e.g. "mfa_required"
                    body["code"] = exc.code
                return JSONResponse(body, status_code=code)
        log.error("unhandled vault error: %s", type(exc).__name__)
        return JSONResponse({"error": "Request failed."}, status_code=500)

    @app.exception_handler(Exception)
    async def unexpected_error(_: Request, exc: Exception):
        # FAIL CLOSED with a generic body: nothing about the cause is revealed to the client.
        log.error("unexpected error: %s", type(exc).__name__)
        return JSONResponse({"error": "Request failed."}, status_code=500)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        if request.url.path.startswith("/api"):
            response.headers["Cache-Control"] = "no-store"
            token = getattr(request.state, "session_token_out", None)
            if token:  # refreshed session token; the browser keeps it in memory only
                response.headers["X-Session-Token"] = token
        if not request.url.path.startswith("/docs") and request.url.path != "/openapi.json":
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'"
            )
        return response

    def done(request: Request, payload):
        """Attach the refreshed session token (if a session was presented) and return the payload."""
        result = getattr(request.state, "auth", None)
        if result is not None:
            request.state.session_token_out = refresh_token(result, get_settings())
        return payload

    # --------------------------------------------------------------- status
    @app.get("/api/status")
    def status(request: Request):
        # PUBLIC on purpose (no secrets). It deliberately does NOT say whether MFA is enabled.
        vault = vault_for(request)
        settings = get_settings()
        policy = policy_from_settings(settings)
        out = {"initialized": vault.initialized, "storage": settings.storage_backend,
               "max_upload_bytes": settings.max_upload_bytes,
               "min_passphrase_length": settings.min_passphrase_length,
               "kem": "ML-KEM-768", "kdf": "Argon2id", "cipher": "AES-256-GCM",
               "lockout_policy": policy.to_public_dict(),
               "session_policy": {"ttl_seconds": settings.session_ttl_seconds,
                                  "idle_seconds": settings.session_idle_seconds,
                                  "reauth_window_seconds": settings.reauth_window_seconds}}
        if vault.initialized:
            ks = vault.backend.load_keystore()
            entries = vault.audit_entries()
            result = chain.verify(entries)
            now = vault.clock()
            # Key age comes from the audit log (no keystore change): the last rotation, else creation.
            stamps = [e["ts"] for e in entries if e["event"] in ("rotate_keys", "vault_created")]
            out.update(key_version=ks["active_version"], files=len(vault.backend.list_meta()),
                       audit_ok=result.ok, audit_length=result.length, audit_head=result.head_hash,
                       model_loaded=vault.detector().model is not None,
                       key_age_days=int((now - stamps[-1]) // 86400) if stamps else None)
            with contextlib.suppress(Exception):  # informational only: this caller's own lockout state
                tail = vault.backend.read_audit_tail(500)
                decision = check_lockout(tail, now, vault.actor, policy)
                out["lockout"] = {"locked": not decision.allowed, "retry_after": decision.retry_after,
                                  "failures_in_window": failures_in_window(tail, now, vault.actor, policy)}
        return out

    @app.post("/api/init", status_code=201)
    def init(body: InitRequest, request: Request):
        Vault.initialize(make_backend(), body.passphrase, actor=actor_for(request), clock=now_fn)
        return {"ok": True}

    # -------------------------------------------------------------- session
    def session_payload(auth_result, claims: sess.SessionClaims, token: str) -> dict:
        s = get_settings()
        return {"token": token, "expires_in": max(0, int(claims.exp - auth_result.vault.clock())),
                "idle_timeout": s.session_idle_seconds, "reauth_window": s.reauth_window_seconds,
                "authenticated_at": claims.ra}  # time of the successful unlock that opened/renewed it

    @app.post("/api/session")
    def create_session(body: SessionRequest, request: Request):
        """Open a session: passphrase, plus a TOTP code when MFA is on (checked in that order)."""
        r = auth(request, body.passphrase, body.totp_code, sensitive=True, use_session=False)
        vault, settings = r.vault, get_settings()
        claims = sess.new_claims(vault.clock(), sess.policy_from_settings(settings), mfa_verified=r.mfa_verified_now)
        vault.record_event("session_created", {"sid": sess.sid_fingerprint(claims.sid)})
        token = sess.encode(sess.secret_from_settings(settings, warn=log.warning), claims)
        request.state.auth = None  # a brand-new token is returned in the body
        return session_payload(r, claims, token)

    @app.post("/api/session/reauth")
    def reauthenticate(body: SessionRequest, request: Request):
        """Re-prove identity inside an existing session. A code is REQUIRED when MFA is on."""
        settings = get_settings()
        if not bearer_token(request):
            raise SessionInvalid("no session")
        r = auth(request, body.passphrase, body.totp_code, sensitive=True, require_code=True)
        if r.claims is None:
            raise SessionInvalid("no session")
        claims = sess.touch(r.claims, r.vault.clock(), reauthenticated=True, mfa_verified=r.mfa_verified_now)
        r.vault.record_event("reauthenticated", {"sid": sess.sid_fingerprint(claims.sid)})
        token = sess.encode(sess.secret_from_settings(settings, warn=log.warning), claims)
        request.state.auth = None
        return session_payload(r, claims, token)

    @app.post("/api/session/logout")
    def logout(request: Request):
        """Revoke the presented session. The revocation is a record in the audit chain, which is how a
        stateless server remembers it. Idempotent: an unusable token just returns ok."""
        token = bearer_token(request)
        if token:
            try:
                settings = get_settings()
                claims = sess.decode(sess.secret_from_settings(settings, warn=log.warning), token)
                vault = vault_for(request)
                fp = sess.sid_fingerprint(claims.sid)
                if not any(e["event"] == "session_revoked" and e["details"].get("sid") == fp
                           for e in vault.audit_since(claims.iat)):
                    vault.record_event("session_revoked", {"sid": fp})
            except SessionInvalid:
                pass
        return {"ok": True}

    # ------------------------------------------------------------------ MFA
    @app.get("/api/mfa/status")
    def mfa_status(request: Request):
        """MFA state is shown ONLY to the holder of a valid session. A session can only be opened with
        the passphrase (and a code when MFA is on), so the state is never revealed to someone who has not
        passed the passphrase check, and the passphrase never has to travel in a URL."""
        vault = vault_for(request)
        token = bearer_token(request)
        if not token:
            raise SessionInvalid("no session")
        claims = load_session(vault, token, get_settings())
        request.state.auth = AuthResult(vault, claims)
        return done(request, {"enabled": vault.mfa_required})

    @app.post("/api/mfa/enroll")
    def mfa_enroll(body: PassphraseRequest, request: Request):
        r = auth(request, body.passphrase, sensitive=False)
        secret, uri = r.vault.mfa_begin_enrollment()  # persists nothing
        payload = {"secret": secret, "uri": uri, "qr": _qr_data_uri(uri)}
        return done(request, JSONResponse(payload, headers={"Cache-Control": "no-store"}))

    @app.post("/api/mfa/confirm")
    def mfa_confirm(body: MfaConfirmRequest, request: Request):
        r = auth(request, body.passphrase, sensitive=False)
        r.vault.mfa_confirm_enrollment(body.secret.upper(), body.code)
        return done(request, {"ok": True})

    @app.post("/api/mfa/disable")
    def mfa_disable(body: MfaDisableRequest, request: Request):
        # Always needs a fresh code (a session is not enough to remove the second factor).
        r = auth(request, body.passphrase, sensitive=False)
        r.vault.mfa_disable(body.totp_code)
        return done(request, {"ok": True})

    # ---------------------------------------------------------------- files
    @app.get("/api/files")
    def list_locked(request: Request):
        return [_info(f) for f in vault_for(request).list_files()]

    @app.post("/api/files/list")
    def list_unlocked(body: PassphraseRequest, request: Request):
        r = auth(request, body.passphrase, sensitive=False)  # routine browsing: passphrase only
        return done(request, [_info(f) for f in r.vault.list_files()])

    @app.post("/api/files", status_code=201)
    async def upload(request: Request, file: UploadFile = File(...), passphrase: str = Form(..., max_length=256)):
        # Require the passphrase: otherwise anyone who finds a hosted vault could fill its storage.
        r = auth(request, passphrase, sensitive=False)  # upload: passphrase only
        limit = get_settings().max_upload_bytes
        data = bytearray()
        while chunk := await file.read(64 * 1024):
            data += chunk
            if len(data) > limit:
                raise UploadTooLarge(f"File is larger than the {limit // 1024} KB limit.")
        return done(request, _info(r.vault.upload(file.filename or "unnamed", bytes(data))))

    @app.post("/api/files/{file_id}/download")
    def download(file_id: str, body: PassphraseRequest, request: Request):
        r = auth(request, body.passphrase, body.totp_code, sensitive=True)
        name, data = r.vault.download(file_id)
        safe = quote(Path(name).name or "download")
        done(request, None)
        return Response(
            data, media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename*=UTF-8''{safe}"},
        )

    @app.post("/api/files/{file_id}/delete")
    def delete(file_id: str, body: PassphraseRequest, request: Request):
        r = auth(request, body.passphrase, body.totp_code, sensitive=True)
        r.vault.delete(file_id)
        return done(request, {"ok": True})

    # ------------------------------------------------------------- rotation
    @app.post("/api/rotate/passphrase")
    def rotate_passphrase(body: RotatePassphraseRequest, request: Request):
        r = auth(request, body.passphrase, body.totp_code, sensitive=True)
        r.vault.rotate_passphrase(body.new_passphrase)
        return done(request, {"ok": True})

    @app.post("/api/rotate/keys")
    def rotate_keys(body: PassphraseRequest, request: Request):
        r = auth(request, body.passphrase, body.totp_code, sensitive=True)
        return done(request, {"files_rewrapped": r.vault.rotate_keys()})

    # ------------------------------------------------------ audit + monitor
    @app.get("/api/audit")
    def audit(request: Request, limit: int = 50):
        # PUBLIC on purpose, like /api/status: it holds event names and hashes, never secrets. Anyone can
        # therefore see security events (including MFA ones); see docs/THREAT_MODEL.md.
        vault = vault_for(request)
        entries = vault.audit_entries()
        result = chain.verify(entries)
        return {
            "ok": result.ok, "length": result.length, "head": result.head_hash,
            "problem": None if result.ok else {"index": result.first_bad_index, "reason": result.reason},
            "entries": entries[-max(1, min(limit, 500)):][::-1],
        }

    @app.post("/api/security/scan")
    def security_scan(body: PassphraseRequest, request: Request):
        # Deliberate contract change (Phase 3): a scan writes alerts into the audit chain, so it now
        # needs the passphrase (and a code or recent MFA session when MFA is on). It was open before.
        r = auth(request, body.passphrase, body.totp_code, sensitive=True)
        out = r.vault.scan(record=True).to_dict()
        out["alerts"] = out["alerts"][-100:][::-1]
        return done(request, out)

    # --------------------------------------------------------------- web ui
    if WEB_DIR.exists():
        app.mount("/assets", StaticFiles(directory=WEB_DIR), name="assets")

        @app.get("/", include_in_schema=False)
        def index():
            return FileResponse(WEB_DIR / "index.html")

    return app


app = create_app()
