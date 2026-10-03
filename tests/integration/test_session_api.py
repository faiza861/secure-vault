"""API policy: MFA gating, sessions, reauthentication, logout, lockout, response shapes."""

import json

import pytest
from fastapi.testclient import TestClient
from tests.conftest import FakeClock

import securevault.storage as storage_pkg
from securevault.api.main import create_app
from securevault.config import get_settings
from securevault.core import totp

PW = "session test passphrase"
BAD = "wrong wrong wrong"


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("STORAGE_BACKEND", "memory")
    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "none.json"))
    monkeypatch.setenv("SESSION_SECRET", "t" * 40)
    get_settings.cache_clear()
    storage_pkg._memory_singleton = None
    clk = FakeClock()
    c = TestClient(create_app(clock=clk))
    c.post("/api/init", json={"passphrase": PW})
    yield c, clk
    get_settings.cache_clear()
    storage_pkg._memory_singleton = None


def code(secret, clk, offset=0):
    return totp.totp(secret, clk() + offset)


def enable_mfa(c, clk):
    r = c.post("/api/mfa/enroll", json={"passphrase": PW})
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    body = r.json()
    assert set(body) == {"secret", "uri", "qr"} and body["uri"].startswith("otpauth://totp/")
    assert body["qr"] is None or body["qr"].startswith("data:image/svg+xml")
    assert c.get("/api/mfa/status").status_code == 401  # nothing persisted yet, and no session anyway
    r = c.post("/api/mfa/confirm", json={"passphrase": PW, "secret": body["secret"], "code": code(body["secret"], clk)})
    assert r.status_code == 200
    clk.advance(30)
    return body["secret"]


def upload(c):
    return c.post("/api/files", files={"file": ("a.txt", b"hello")}, data={"passphrase": PW}).json()["file_id"]


def test_status_shape_and_no_mfa_oracle(env):
    c, clk = env
    s = c.get("/api/status").json()
    assert s["key_version"] == 1 and s["lockout_policy"]["max_failures"] == 5 and s["key_age_days"] == 0
    assert s["lockout"] == {"locked": False, "retry_after": 0, "failures_in_window": 0}
    enable_mfa(c, clk)
    s2 = c.get("/api/status").json()
    assert "mfa_enabled" not in s2 and "mfa" not in json.dumps(s2).lower()  # public endpoint never says


def test_legacy_flow_unchanged_when_mfa_off(env):
    c, _clk = env
    fid = upload(c)
    assert c.post(f"/api/files/{fid}/download", json={"passphrase": PW}).content == b"hello"  # no totp_code
    assert c.post("/api/rotate/keys", json={"passphrase": PW}).status_code == 200
    assert c.post("/api/security/scan", json={"passphrase": PW}).status_code == 200
    assert c.post(f"/api/files/{fid}/delete", json={"passphrase": PW}).status_code == 200


def test_mfa_gates_sensitive_actions_not_routine_ones(env):
    c, clk = env
    fid = upload(c)
    secret = enable_mfa(c, clk)
    # routine: passphrase only
    assert c.post("/api/files/list", json={"passphrase": PW}).status_code == 200
    assert c.post("/api/files", files={"file": ("b.txt", b"x")}, data={"passphrase": PW}).status_code == 201
    # sensitive: 401 mfa_required (only after the passphrase is right)
    for path, body in [(f"/api/files/{fid}/download", {}), (f"/api/files/{fid}/delete", {}),
                       ("/api/rotate/keys", {}), ("/api/security/scan", {}),
                       ("/api/rotate/passphrase", {"new_passphrase": "another passphrase!"})]:
        r = c.post(path, json={"passphrase": PW, **body})
        assert r.status_code == 401 and r.json()["code"] == "mfa_required", path
    # wrong passphrase: the normal error, with no hint that MFA exists
    r = c.post(f"/api/files/{fid}/download", json={"passphrase": BAD})
    assert r.status_code == 401 and r.json() == {"error": "Wrong passphrase."}
    # wrong / malformed code
    r = c.post(f"/api/files/{fid}/download", json={"passphrase": PW, "totp_code": "000000"})
    assert r.status_code == 401 and r.json()["code"] == "invalid_mfa_code"
    assert c.post(f"/api/files/{fid}/download", json={"passphrase": PW, "totp_code": "abc"}).status_code == 422
    # correct code works once; replay is refused
    good = code(secret, clk)
    assert c.post(f"/api/files/{fid}/download", json={"passphrase": PW, "totp_code": good}).content == b"hello"
    r = c.post(f"/api/files/{fid}/download", json={"passphrase": PW, "totp_code": good})
    assert r.status_code == 401 and r.json()["code"] == "invalid_mfa_code"


def test_session_flow_recent_auth_and_reauthentication(env):
    c, clk = env
    fid = upload(c)
    secret = enable_mfa(c, clk)
    # opening a session needs the code
    assert c.post("/api/session", json={"passphrase": PW}).json()["code"] == "mfa_required"
    r = c.post("/api/session", json={"passphrase": PW, "totp_code": code(secret, clk)})
    assert r.status_code == 200
    sj = r.json()
    assert set(sj) == {"token", "expires_in", "idle_timeout", "reauth_window", "authenticated_at"}
    assert sj["expires_in"] == 900 and sj["authenticated_at"] == clk()
    h = {"Authorization": f"Bearer {sj['token']}"}
    # recent MFA-verified session stands in for a code
    r = c.post(f"/api/files/{fid}/download", json={"passphrase": PW}, headers=h)
    assert r.status_code == 200 and r.content == b"hello" and r.headers["x-session-token"]
    assert c.get("/api/mfa/status", headers=h).json() == {"enabled": True}
    # activity keeps the session alive but does NOT extend the "recent authentication" window
    clk.advance(200)
    h = {"Authorization": f"Bearer {c.post('/api/files/list', json={'passphrase': PW}, headers=h).headers['x-session-token']}"}
    clk.advance(200)  # 400 s since authentication > 300 s reauth window; 200 s idle < 300 s
    r = c.post(f"/api/files/{fid}/download", json={"passphrase": PW}, headers=h)
    assert r.status_code == 401 and r.json()["code"] == "mfa_required"
    # reauthentication needs a fresh code, then the session works again without one
    assert c.post("/api/session/reauth", json={"passphrase": PW}, headers=h).json()["code"] == "mfa_required"
    r = c.post("/api/session/reauth", json={"passphrase": PW, "totp_code": code(secret, clk)}, headers=h)
    assert r.status_code == 200
    h2 = {"Authorization": f"Bearer {r.json()['token']}"}
    assert c.post(f"/api/files/{fid}/download", json={"passphrase": PW}, headers=h2).status_code == 200
    events = [e["event"] for e in c.get("/api/audit?limit=100").json()["entries"]]
    assert {"session_created", "reauthenticated", "mfa_ok"} <= set(events)


def test_session_expiry_inactivity_and_absolute(env):
    c, clk = env
    token = c.post("/api/session", json={"passphrase": PW}).json()["token"]  # MFA off: passphrase only
    h = {"Authorization": f"Bearer {token}"}
    clk.advance(299)
    r = c.post("/api/files/list", json={"passphrase": PW}, headers=h)
    assert r.status_code == 200
    h = {"Authorization": f"Bearer {r.headers['x-session-token']}"}
    clk.advance(301)  # idle timeout
    r = c.post("/api/files/list", json={"passphrase": PW}, headers=h)
    assert r.status_code == 401 and r.json()["code"] == "session_expired"
    assert any(e["event"] == "session_expired" for e in c.get("/api/audit").json()["entries"])
    # absolute lifetime: keep it busy, it still dies at 900 s
    clk.advance(1)
    tok = c.post("/api/session", json={"passphrase": PW}).json()["token"]
    for _ in range(4):
        clk.advance(200)
        r = c.post("/api/files/list", json={"passphrase": PW}, headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        tok = r.headers["x-session-token"]
    clk.advance(200)  # 1000 s after creation
    assert c.post("/api/files/list", json={"passphrase": PW}, headers={"Authorization": f"Bearer {tok}"}).status_code == 401


def test_invalid_forged_and_wrong_secret_sessions(env):
    c, clk = env
    token = c.post("/api/session", json={"passphrase": PW}).json()["token"]
    for bad in ["garbage", token[:-3] + "AAA", "v1..", token + "x" * 700]:
        r = c.post("/api/files/list", json={"passphrase": PW}, headers={"Authorization": f"Bearer {bad}"})
        assert r.status_code == 401 and r.json()["code"] == "session_invalid", bad[:10]
    assert c.get("/api/mfa/status").status_code == 401  # no session at all
    # a token signed with a different secret (e.g. another deployment) is rejected
    from securevault.security import session as s

    forged = s.encode(b"z" * 32, s.new_claims(clk(), s.SessionPolicy(), mfa_verified=True))
    assert c.get("/api/mfa/status", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_pre_mfa_session_cannot_stand_in_for_a_code(env):
    c, clk = env
    fid = upload(c)
    token = c.post("/api/session", json={"passphrase": PW}).json()["token"]  # created while MFA was off
    h = {"Authorization": f"Bearer {token}"}
    enable_mfa(c, clk)
    r = c.post(f"/api/files/{fid}/download", json={"passphrase": PW}, headers=h)
    assert r.status_code == 401 and r.json()["code"] == "mfa_required"


def test_logout_invalidates_the_session(env):
    c, _clk = env
    token = c.post("/api/session", json={"passphrase": PW}).json()["token"]
    h = {"Authorization": f"Bearer {token}"}
    assert c.post("/api/files/list", json={"passphrase": PW}, headers=h).status_code == 200
    assert c.post("/api/session/logout", headers=h).json() == {"ok": True}
    r = c.post("/api/files/list", json={"passphrase": PW}, headers=h)
    assert r.status_code == 401 and r.json()["code"] == "session_invalid"
    assert c.post("/api/session/logout", headers=h).status_code == 200  # idempotent
    assert c.post("/api/session/logout").status_code == 200  # no token: harmless
    ev = [e["event"] for e in c.get("/api/audit?limit=100").json()["entries"]]
    assert ev.count("session_revoked") == 1


def test_disable_needs_code_and_returns_to_legacy(env):
    c, clk = env
    fid = upload(c)
    secret = enable_mfa(c, clk)
    assert c.post("/api/mfa/disable", json={"passphrase": PW}).status_code == 422  # a code is mandatory
    r = c.post("/api/mfa/disable", json={"passphrase": PW, "totp_code": "000000"})
    assert r.status_code == 401 and r.json()["code"] == "invalid_mfa_code"
    assert c.post("/api/mfa/disable", json={"passphrase": PW, "totp_code": code(secret, clk)}).status_code == 200
    assert c.post(f"/api/files/{fid}/download", json={"passphrase": PW}).status_code == 200  # no code needed again
    assert c.post("/api/mfa/enroll", json={"passphrase": PW}).status_code == 200  # can enroll again


def test_enroll_twice_and_bad_confirm(env):
    c, clk = env
    secret = enable_mfa(c, clk)
    assert c.post("/api/mfa/enroll", json={"passphrase": PW}).status_code == 409
    assert c.post("/api/mfa/confirm", json={"passphrase": PW, "secret": secret, "code": "123456"}).status_code == 409
    assert c.post("/api/mfa/enroll", json={"passphrase": BAD}).status_code == 401


def test_lockout_429_includes_mfa_failures_and_blocks_correct_code(env):
    c, clk = env
    fid = upload(c)
    secret = enable_mfa(c, clk)
    for i in range(4):
        r = c.post(f"/api/files/{fid}/download", json={"passphrase": PW, "totp_code": "000000"})
        assert r.status_code == 401, i
    r = c.post(f"/api/files/{fid}/download", json={"passphrase": PW, "totp_code": "000000"})
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    r = c.post(f"/api/files/{fid}/download", json={"passphrase": PW, "totp_code": code(secret, clk)})
    assert r.status_code == 429  # even a correct code is refused while locked out
    s = c.get("/api/status").json()["lockout"]
    assert s["locked"] is True and s["retry_after"] >= 1
    clk.advance(61)
    clk.advance(30)
    ok = c.post(f"/api/files/{fid}/download", json={"passphrase": PW, "totp_code": code(secret, clk)})
    assert ok.status_code == 200


def test_x_forwarded_for_is_not_trusted(env):
    c, _clk = env
    for i in range(5):
        c.post("/api/files/list", json={"passphrase": BAD}, headers={"X-Forwarded-For": f"9.9.9.{i}"})
    r = c.post("/api/files/list", json={"passphrase": PW}, headers={"X-Forwarded-For": "1.2.3.4"})
    assert r.status_code == 429  # rotating the header did not dodge the per-actor limit


def test_no_secrets_in_audit_or_status(env):
    c, clk = env
    secret = enable_mfa(c, clk)
    c0 = code(secret, clk)
    token = c.post("/api/session", json={"passphrase": PW, "totp_code": c0}).json()["token"]
    c.post("/api/files/list", json={"passphrase": BAD})
    dump = json.dumps(c.get("/api/audit?limit=500").json()) + json.dumps(c.get("/api/status").json())
    for secret_value in (PW, BAD, secret, c0, token, token.split(".")[2]):
        assert secret_value not in dump


def test_unexpected_errors_fail_closed_with_generic_body(env, monkeypatch):
    _c, clk = env
    from securevault.storage import vault as vault_mod

    def boom(self, *a, **k):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(vault_mod.Vault, "list_files", boom)
    client = TestClient(create_app(clock=clk), raise_server_exceptions=False)
    r = client.post("/api/files/list", json={"passphrase": PW})
    assert r.status_code == 500 and r.json() == {"error": "Request failed."}
