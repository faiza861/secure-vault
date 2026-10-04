# Changelog

## Deployment fix

### Fixed

- `pyproject.toml` now lists the runtime dependencies (same as `requirements.txt`). Before, it listed none, so a
  platform that reads `pyproject.toml` (such as Vercel) could install nothing and the app failed to start.
- `tests/unit/test_dependencies_in_sync.py` keeps the two lists identical.

## Easy start (no change to the app itself)

### Added

- `start.py`: one-step launcher. Creates `.venv`, installs runtime libraries, writes a local `.env` with a random
  `SESSION_SECRET` (only if none exists), starts the app on `127.0.0.1` and opens the browser. Picks the next free
  port if 8000 is busy; stops cleanly on Ctrl+C.
- `Start-SecureVault.bat` (Windows double-click) and `start.sh` (macOS/Linux) call the launcher.
- `tests/unit/test_start_script.py`: tests for the launcher's helper functions.
- README: plain-English overview, "choose your way" table, architecture diagram, glossary. `.gitattributes` for line endings.

### Unchanged

- Everything under `src/`, `web/`, `models/` and the existing tests. No Docker files were added because they could not
  be tested in the development environment.

## Enhanced edition: access protection

### Added

- **Audit tail read** (`StorageBackend.read_audit_tail`): `Vault._log` reads only the newest entry (memory, local, Postgres).
- **Lockout** (`security/lockout.py`): pure, derived from the audit log; per client 5 failures / 300 s, global backstop 20,
  progressive 60 s -> 300 s -> hard cap 900 s. Runs before Argon2id for both CLI and API. API returns 429 + `Retry-After`.
  New events: `unlock_failed`, `mfa_failed`, `lockout`. Settings: `RATE_LIMIT_*`, `LOCKOUT_*`.
- **TOTP MFA** (`core/totp.py`, `core/mfa_secret.py`): RFC 6238 on the standard library; secret stored as an optional,
  AES-256-GCM-encrypted `mfa` keystore block under an HKDF subkey of the KEK. Replay protection via logged `mfa_ok` steps.
  Passphrase change re-encrypts the block atomically. CLI: `securevault mfa status|disable`.
- **Sessions** (`security/session.py`, `api/auth.py`): signed stateless tokens, absolute + idle expiry, reauthentication,
  logout via `session_revoked` audit records. Endpoints: `/api/session`, `/api/session/reauth`, `/api/session/logout`,
  `/api/mfa/status|enroll|confirm|disable`. `/api/status` adds `key_version`, `key_age_days`, `lockout_policy`.
- **Web UI**: logo, System/Light/Dark theme (`theme.js`, no flash), responsive layout, posture strip, Access Protection
  card, native unlock dialog, MFA enrollment card. Strict CSP kept (no inline script/style, no external resources).
- Dependency: `segno` (pure Python, QR code for enrollment).
- Docs: threat model, architecture (sensitive-action table, check order), README, `.env.example`.

### Changed (deliberate contract changes)

- `POST /api/security/scan` now requires the passphrase in the request body (it was unauthenticated).
- A 5th wrong passphrase in a window now returns 429 instead of 401; later attempts, even correct ones, are refused until the lockout ends.
- Tests adjusted for these: `test_audit_and_security_scan`, `test_scan_flags_brute_force_and_records_alert_once`
  (limiter raised for those tests only; assertions kept).

### Unchanged

- Crypto in `core/` (envelope, KDF, cipher, PQC, integrity), `chain.make_entry` hashing, the anomaly feature vector,
  and `models/` (byte-identical). Vaults without an `mfa` block load and operate as before.
