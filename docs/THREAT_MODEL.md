# Threat model

## What we protect
File contents and file names; the integrity of stored data; the integrity of the activity history.

## Adversaries and what happens

| Adversary | Outcome |
|---|---|
| Steals the disk or database dump | Sees only ciphertext, wrapped keys and a keystore. Must break AES-256-GCM or brute-force the passphrase against Argon2id (about 0.25 s and 64 MiB per guess). |
| Records encrypted files today, owns a quantum computer later ("harvest now, decrypt later") | File keys are wrapped with ML-KEM-768 and AES-256, neither of which Shor's algorithm breaks. The passphrase-derived layer still depends on passphrase strength. |
| Modifies or swaps stored ciphertext | AES-GCM authentication, the ciphertext hash and the file-id binding all fail. The attempt is logged as `integrity_failure`. |
| Edits or deletes audit history | Chain verification reports the first broken entry. |
| Rewrites the whole audit log with fresh hashes, or truncates it | Detected only if you saved the head hash (the "anchor") elsewhere and verify with it. |
| Guesses the passphrase or authenticator code online (including credential stuffing) | Every failed unlock or code is logged. Five failures from one client in 300 s start a progressive lockout (60 s, then 300 s, then up to a hard cap of 900 s); 20 failures from all clients combined trigger the same lockout globally. The check runs before Argon2id, so a flood does not burn CPU. The monitor rule still raises an alert. |
| Knows the passphrase but not the authenticator (TOTP MFA enabled) | Sensitive actions (download, delete, key and passphrase rotation, scan, MFA disable) need a current code or a recent MFA-verified session. Wrong passphrase gives the usual error and never reveals whether MFA is on. A code works once (replay is rejected). |
| Steals a session token | The token holds no passphrase or key material, expires (15 min absolute, 5 min idle by default) and is revoked on sign out. It cannot decrypt anything by itself. |
| Behaves oddly with valid access (night downloads, bulk copying) | Rules and the Isolation Forest raise alerts. |
| Path traversal through file ids or names | File ids must be 32 hex characters; downloaded names are reduced to their last path component. |
| Script injection through a hostile file name in the web UI | The UI inserts data with `textContent`; the API sends a strict Content-Security-Policy. |

## Out of scope and known limitations (be upfront about these)

* **Hosted mode is not zero-knowledge.** The server decrypts, so the operator can see the passphrase and plaintext
  while a request runs. Only the CLI is fully local. Browser-side encryption would fix this and is future work.
* **Pure-Python ML-KEM** (`kyber-py`) is not hardened against timing or other side channels. Use liboqs for production.
* **No memory zeroisation.** Python cannot reliably wipe keys from memory.
* **Lockout can be abused for denial of service.** Anyone who can reach the API can deliberately fail logins and
  lock the owner out, but only for at most the capped duration (900 s). We accept this over permanent lockout.
* **The audit-log rate limiter is best-effort.** State is recomputed from the log, so it works across restarts and
  serverless instances, but simultaneous requests can overshoot the limit by a few attempts. Blocked attempts are
  not individually logged (only the `lockout` event), so a flood cannot bloat the log.
* **`X-Forwarded-For` is not trusted** (a client can forge it). The per-client limit uses the socket address, so
  behind a proxy all clients look like one; the global backstop is what protects the vault in that case.
* **MFA protects the online path only.** Someone with the disk or database dump attacks the passphrase offline
  with Argon2id and never meets MFA.
* **The CLI is the MFA recovery path.** `securevault mfa disable` needs only the passphrase, because local disk
  access already means ownership and a lost authenticator must not destroy access to the files. It is logged.
* **TOTP is not phishing-resistant.** A fake site can relay a valid code in real time. It raises the cost of
  guessing; it does not stop phishing.
* **The browser holds the passphrase in memory** (never in storage, cookies or the URL) because the stateless
  server derives keys on every request. It is cleared on sign out and after 5 minutes idle. A script injected into
  the page could read it, which is why the CSP forbids inline script and external resources.
* **Sessions are stateless.** There is no server-side session table; revocation is a record in the audit chain.
  Sessions need `SESSION_SECRET` set to survive restarts and to work across serverless instances.
* **`/api/status` and `/api/audit` are public** by design. They expose event names, counts, hashes, key version
  and lockout policy, never secrets. Anyone can therefore see that security events (such as MFA changes) occurred.
  `/api/status` does not state whether MFA is enabled; that is shown only to a signed-in session.
* **Metadata leaks:** file count, sizes, upload times and key versions are visible.
* **The AI model is trained on simulated logs.** It demonstrates the technique; it has not been validated on
  real usage. See `docs/EVALUATION.md`.
* **A single passphrase protects everything.** Losing it means losing the data; there is no recovery.
* Optional TOTP MFA and short sessions now exist, but there is no multi-user access control and no secure deletion on disk.
