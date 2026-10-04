# Deployment guide

This guide is for developers who want to host their own copy. It is not needed to use the app: to try Secure Vault,
use the live demo or run it on your own computer (see the main [README](../README.md)).

## Deploy for free (GitHub + Vercel + Neon)

The live demo linked in the README runs on this setup (Vercel Hobby plan and Neon free tier).

1. Push this repo to GitHub.
2. Create a free Postgres database at neon.com. In **Connect**, turn on **Show password**, copy the connection string,
   and make sure it is one line ending in `?sslmode=require`.
3. Import the repo in Vercel. Under **Environment Variables** set:

   | Name | Value |
   | --- | --- |
   | `STORAGE_BACKEND` | `postgres` |
   | `DATABASE_URL` | the Neon string from step 2 |
   | `SESSION_SECRET` | a long random value (`python -c "import secrets; print(secrets.token_urlsafe(48))"`) |
   | `TZ_OFFSET_HOURS` | your UTC offset in hours (optional) |

4. Deploy. `api/index.py` exposes the FastAPI app; `vercel.json` includes the `web/`, `models/` and `src/` folders.
   Dependencies come from `pyproject.toml`, which must list the same libraries as `requirements.txt` (a test checks this).
5. For a public demo, also set `DEMO_MODE` and `MAX_UPLOAD_BYTES` (see the section above), then create the vault yourself straight
   away, because the first visitor to an empty deployment can create it.

Never put the Neon string or `SESSION_SECRET` in the repository or in a chat. If the page shows "Request failed",
open the project's **Logs** in Vercel; a `ProgrammingError` or `OperationalError` points to the `DATABASE_URL` value.

## Running a shared public demo

A public demo is one vault that every visitor shares. To stop a curious visitor from locking everyone out (by
changing the passphrase or switching on two-step verification), set these in Vercel under **Environment Variables**:

| Name | Value | Why |
| --- | --- | --- |
| `DEMO_MODE` | `true` | Turns off passphrase change and two-step verification setup; shows a notice on the page |
| `MAX_UPLOAD_BYTES` | `1048576` | Limits each upload to 1 MB so the free database does not fill up |

Visitors can still add, list, download and delete files, rotate keys, run the security scan and view the audit chain.
`DEMO_MODE` is off by default and changes nothing on a normal install. If someone makes a mess, empty the demo in Neon's
SQL Editor with `TRUNCATE sv_files, sv_keystore, sv_audit;` and create the vault again.
