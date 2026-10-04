"""DEMO_MODE: the shared public demo refuses the few actions that would lock every visitor out."""

import pytest
from fastapi.testclient import TestClient

import securevault.storage as storage_pkg
from securevault.config import get_settings

PW = "demo mode passphrase"


def make_client(monkeypatch, tmp_path, demo: bool):
    monkeypatch.setenv("STORAGE_BACKEND", "memory")
    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "none.json"))
    monkeypatch.setenv("DEMO_MODE", "true" if demo else "false")
    get_settings.cache_clear()
    storage_pkg._memory_singleton = None
    from securevault.api.main import create_app

    return TestClient(create_app())


@pytest.fixture(autouse=True)
def _reset():
    yield
    get_settings.cache_clear()
    storage_pkg._memory_singleton = None


def test_demo_blocks_lockout_causing_actions_without_looking_at_credentials(monkeypatch, tmp_path):
    client = make_client(monkeypatch, tmp_path, demo=True)
    client.post("/api/init", json={"passphrase": PW})
    attempts = [
        ("/api/mfa/enroll", {"passphrase": PW}),
        ("/api/mfa/confirm", {"passphrase": PW, "secret": "A" * 32, "code": "123456"}),
        ("/api/mfa/disable", {"passphrase": PW, "totp_code": "123456"}),
        ("/api/rotate/passphrase", {"passphrase": PW, "new_passphrase": "another passphrase"}),
    ]
    for path, payload in attempts:
        r = client.post(path, json=payload)
        assert r.status_code == 403 and r.json()["code"] == "demo_restricted", path
    # nothing was processed: even a WRONG passphrase gets the same answer (no passphrase check happened),
    # so a visitor cannot use these routes to guess or to trip the lockout
    r = client.post("/api/mfa/enroll", json={"passphrase": "wrong wrong wrong"})
    assert r.status_code == 403
    assert client.get("/api/status").json()["lockout"]["failures_in_window"] == 0


def test_demo_still_allows_normal_use(monkeypatch, tmp_path):
    client = make_client(monkeypatch, tmp_path, demo=True)
    client.post("/api/init", json={"passphrase": PW})
    assert client.get("/api/status").json()["demo_mode"] is True
    up = client.post("/api/files", files={"file": ("a.txt", b"hello")}, data={"passphrase": PW})
    assert up.status_code == 201
    listed = client.post("/api/files/list", json={"passphrase": PW}).json()
    assert len(listed) == 1
    fid = listed[0]["file_id"]
    assert client.post(f"/api/files/{fid}/download", json={"passphrase": PW}).content == b"hello"
    assert client.post("/api/rotate/keys", json={"passphrase": PW}).status_code == 200
    assert client.post("/api/security/scan", json={"passphrase": PW}).status_code == 200
    assert client.post("/api/session", json={"passphrase": PW}).status_code == 200


def test_off_by_default_changes_nothing(monkeypatch, tmp_path):
    client = make_client(monkeypatch, tmp_path, demo=False)
    client.post("/api/init", json={"passphrase": PW})
    assert client.get("/api/status").json()["demo_mode"] is False
    r = client.post("/api/mfa/enroll", json={"passphrase": PW})
    assert r.status_code == 200 and "secret" in r.json()
    r = client.post("/api/rotate/passphrase", json={"passphrase": PW, "new_passphrase": "another passphrase"})
    assert r.status_code == 200
