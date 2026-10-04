# Security policy

Secure Vault is a learning and portfolio project. It uses standard, well-known techniques (Argon2id, ML-KEM-768,
AES-256-GCM, a hash-chained audit log, TOTP), but it has **not** been independently audited or certified, and it
should not be used to protect information whose loss or exposure would cause serious harm. Reports that help make it
better are welcome.

## Supported versions

Only the latest code on the `main` branch is maintained. There are no separate long-term support versions.

| Version | Supported |
| --- | --- |
| `main` (latest) | Yes |
| Older tags and forks | No |

## How to report a vulnerability

Please report security problems **privately**, not in a public issue, discussion or pull request.

1. Open the repository's **Security** tab and choose **Report a vulnerability**, or go directly to
   <https://github.com/faiza861/secure-vault/security/advisories/new>.
2. Describe the problem, the steps to reproduce it, the affected file or endpoint, and what an attacker could do.
3. Include the commit or release you tested, and your suggestion for a fix if you have one.

Please do **not** include real personal data, real passwords, or real keys in a report. If you found a secret that
looks real (for example a leaked key), say where it is without pasting its value.

## What to expect

This is a one-person student project, so the process is best effort, with no guaranteed response time and no paid
bounty.

* I aim to acknowledge a report within about 7 days.
* I will confirm whether I can reproduce the issue, and tell you what I plan to do about it.
* Confirmed problems are fixed on `main`, and the fix is described in `CHANGELOG.md`.
* I will credit you in the changelog if you want that. Tell me if you would rather stay anonymous.
* Please give me reasonable time to fix a problem before you publish details.

## Scope

In scope:

* The code in this repository: the API (`src/securevault/api`), cryptography wrappers, storage backends, audit chain,
  lockout, sessions, TOTP, anomaly detector and the web interface in `web/`.
* Mistakes in how standard algorithms are used, for example nonce reuse, missing authentication, or secrets that
  end up in logs, audit entries or responses.
* Ways to bypass the lockout, the two-step verification check, session expiry or the audit chain's tamper detection.

Out of scope, because they are known and documented in `docs/THREAT_MODEL.md`:

* The hosted mode is not zero-knowledge: the server decrypts files, so it briefly sees the passphrase and content.
* TOTP is not phishing-resistant, and MFA protects the online path only, not a stolen disk.
* The pure-Python ML-KEM implementation is not hardened against side-channel attacks.
* The lockout can be triggered on purpose by someone who keeps entering wrong passphrases (it is time-limited and
  capped).
* The audit-log rate limiter is best effort across several serverless instances.
* Findings that come from third-party libraries without a way to exploit them here. Please report those to the
  library's maintainers.
* The lab scripts in `demos/`, which deliberately show weak techniques (such as ECB mode or MD5) to explain why they
  are weak. They are not used by the application.

## Testing the live demo

The public demo is a **shared** vault on free hosting. If you test it, please:

* Use only the demo passphrase published in the README and fake files.
* Do not run denial-of-service or high-volume scans, and do not try to fill the storage.
* Do not try to reach other people's data, other services, or the hosting accounts behind it.
* Do not change or delete other visitors' files beyond what the normal interface allows.

If you stay inside these rules, I will treat your testing as good-faith research and will not take action against
you. These rules do not give you permission to test anything other than this repository and its demo.

## Security measures in this repository

GitHub's dependency alerts and security updates (Dependabot), secret scanning with push protection, and CodeQL code
scanning are switched on, and the automated tests run on every push. These reduce risk but do not replace a review
by an expert.
