# Architecture

Secure Vault is a Python library (`src/securevault`) with two thin front ends: a CLI and a FastAPI
service with a small web UI. All security logic lives in the library, which is why it can be tested
without a server.

## Layers

| Layer | Package | Responsibility |
|---|---|---|
| Crypto primitives | `core/` | Pure functions, no I/O: Argon2id (`kdf`), AES-256-GCM (`cipher`), ML-KEM-768 (`pqc`), SHA-256/HMAC (`integrity`), key hierarchy (`envelope`) |
| Security | `security/` | `lockout.py` (rate limit and lockout, pure, derived from the audit log), `session.py` (signed stateless session tokens); `core/totp.py` and `core/mfa_secret.py` (TOTP and its encrypted keystore block); `api/auth.py` (request policy) |
| Audit | `audit/chain.py` | Hash-chained log: build entries, verify the chain |
| Monitor | `monitor/` | Window features, fixed rules, Isolation Forest scorer, hybrid detector, simulator and trainer |
| Storage | `storage/` | `StorageBackend` interface with memory, local-disk and PostgreSQL implementations; `vault.py` orchestrates everything |
| Interfaces | `cli/`, `api/`, `web/` | Typer commands, FastAPI routes, static web UI |

Dependency direction: interfaces -> `storage/vault` -> (`core`, `audit`, `monitor`). `core` imports nothing from the rest.

## Key hierarchy (envelope encryption)

```
passphrase --Argon2id (salt, t=3, m=64 MiB, p=4)--> KEK
KEK --AES-256-GCM--> ML-KEM-768 secret key        (kept in keystore, encrypted)
ML-KEM-768 public key --encapsulate + HKDF-SHA256--> wrap key --AES-256-GCM--> DEK (one per file)
DEK --AES-256-GCM--> file contents and file name
```

* **Upload needs only the public key** (the CLI can upload without a passphrase).
* **Passphrase change** re-encrypts the ML-KEM secret key under a new KEK: constant work, no file touched.
* **Key rotation** makes a new ML-KEM pair and re-wraps each file's 32-byte DEK. File ciphertext never changes.
  It is crash-safe: the new key is stored first, each file records its key version, old keys are dropped last,
  and running the rotation again resumes an interrupted one.
* Every ciphertext is bound to its file id through AES-GCM associated data, so blobs and wrapped keys cannot be
  swapped between files.
* The integrity fingerprint is the SHA-256 of the **ciphertext**. Hashing the plaintext would let someone with
  the metadata test guesses about file contents.

## Audit chain

`hash = SHA-256(canonical JSON of index, ts, event, actor, details, prev_hash)`. Verification recomputes every
hash and link. Alerts from the monitor are written into the same chain. Details never contain passphrases,
keys, file names or plaintext.

## Anomaly detection (the AI part)

1. **Features** per 5-minute window: hour of day (as sine/cosine), requests, MB transferred, failed unlocks,
   distinct files.
2. **Rules** catch known patterns with explicit thresholds (brute force, bursts, bulk transfer, many files,
   night access).
3. **Isolation Forest** is trained with scikit-learn on simulated normal behaviour, then exported to JSON and
   scored by about 40 lines of pure Python (`monitor/model.py`). The pure-Python scorer is verified against
   scikit-learn in the tests (difference below 1e-9). This keeps numpy/scikit-learn out of the deployed
   function and avoids loading pickle files. A SHA-256 sidecar detects a modified model file.
4. The **hybrid** raises an alert if either layer fires.

## Storage backends

| Backend | Use | Notes |
|---|---|---|
| `local` | CLI | Files under `data/vault/`; atomic writes |
| `memory` | tests, throw-away demo | Lost on exit |
| `postgres` | hosted (Neon free tier) | Ciphertext in `BYTEA`; audit slot protected by a primary key so concurrent writers cannot fork the chain |

## Authentication policy (online path)

Check order on every protected request: **lockout check -> passphrase (Argon2id) -> if MFA is on and the action
is sensitive: TOTP code or recent MFA-verified session -> action.** A wrong passphrase always returns the normal
error and never reveals MFA state. Any unexpected error in the lockout, session or MFA checks denies the request.

| Action | Endpoint | Needs |
|---|---|---|
| Upload | `POST /api/files` | Passphrase only |
| List with names | `POST /api/files/list` | Passphrase only |
| Download | `POST /api/files/{id}/download` | Code or recent MFA session |
| Delete | `POST /api/files/{id}/delete` | Code or recent MFA session |
| Rotate keys | `POST /api/rotate/keys` | Code or recent MFA session |
| Change passphrase | `POST /api/rotate/passphrase` | Code or recent MFA session |
| Security scan | `POST /api/security/scan` | Passphrase, plus code or recent MFA session |
| Open session | `POST /api/session` | Passphrase, plus code when MFA is on |
| Re-authenticate | `POST /api/session/reauth` | Passphrase, plus a code when MFA is on |
| Disable MFA | `POST /api/mfa/disable` | Passphrase and a fresh code (a session is not enough) |
| Start / confirm MFA enrollment | `POST /api/mfa/enroll`, `/confirm` | Passphrase; MFA turns on only after a valid code |
| MFA state | `GET /api/mfa/status` | A valid session |
| Sign out | `POST /api/session/logout` | The session token |
| Status, audit (public) | `GET /api/status`, `/api/audit` | Nothing; no secrets |

Without MFA the table collapses to "passphrase only", exactly as before; clients that send no `totp_code` or
session keep working. The security scan previously needed no credentials; it now needs the passphrase because it
writes alerts into the audit chain.

**Sessions** are `v1.<claims>.<HMAC-SHA256>` tokens signed with `SESSION_SECRET`, sent as `Authorization: Bearer`
and kept in browser memory. They carry an absolute expiry, an inactivity time (refreshed in the `X-Session-Token`
response header) and the time of the last MFA-verified authentication. Logout writes `session_revoked` into the
audit chain. The token never contains the passphrase or keys.

**MFA secret storage:** `keystore["mfa"] = {enabled, enc_secret, version}`, AES-256-GCM under an HKDF subkey of the
KEK (info `securevault/mfa/v1`). Changing the passphrase re-encrypts it in the same atomic keystore replace;
key rotation does not touch it. A keystore without the block is a normal MFA-off vault.
