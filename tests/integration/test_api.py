import pytest
from fastapi.testclient import TestClient

import securevault.storage as storage_pkg
from securevault.config import get_settings

PW = "api test passphrase"


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("STORAGE_BACKEND", "memory")
    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "none.json"))
    get_settings.cache_clear()
    storage_pkg._memory_singleton = None
    from securevault.api.main import create_app

    yield TestClient(create_app())
    get_settings.cache_clear()
    storage_pkg._memory_singleton = None


def test_status_before_and_after_init(client):
    assert client.get("/api/status").json()["initialized"] is False
    assert client.post("/api/init", json={"passphrase": PW}).status_code == 201
    s = client.get("/api/status").json()
    assert s["initialized"] and s["audit_ok"] and s["kem"] == "ML-KEM-768"
    assert client.post("/api/init", json={"passphrase": PW}).status_code == 409


def test_weak_passphrase_rejected(client):
    r = client.post("/api/init", json={"passphrase": "short"})
    assert r.status_code == 422 and "at least" in r.json()["error"]


def test_upload_list_download_delete(client):
    client.post("/api/init", json={"passphrase": PW})
    up = client.post("/api/files", files={"file": ("hello.txt", b"hello world")}, data={"passphrase": PW})
    assert up.status_code == 201
    fid = up.json()["file_id"]

    assert client.get("/api/files").json()[0]["name"] is None  # names hidden while locked
    named = client.post("/api/files/list", json={"passphrase": PW}).json()
    assert named[0]["name"] == "hello.txt"

    dl = client.post(f"/api/files/{fid}/download", json={"passphrase": PW})
    assert dl.status_code == 200 and dl.content == b"hello world"
    assert "hello.txt" in dl.headers["content-disposition"]

    assert client.post(f"/api/files/{fid}/download", json={"passphrase": "wrong wrong wrong"}).status_code == 401
    assert client.post(f"/api/files/{fid}/delete", json={"passphrase": PW}).status_code == 200
    assert client.post(f"/api/files/{fid}/download", json={"passphrase": PW}).status_code == 404


def test_upload_size_limit(client, monkeypatch):
    monkeypatch.setenv("MAX_UPLOAD_BYTES", "100")
    get_settings.cache_clear()
    client.post("/api/init", json={"passphrase": PW})
    r = client.post("/api/files", files={"file": ("big.bin", b"x" * 500)}, data={"passphrase": PW})
    assert r.status_code == 413


def test_path_traversal_ids_are_rejected(client):
    client.post("/api/init", json={"passphrase": PW})
    r = client.post("/api/files/..%2F..%2Fetc%2Fpasswd/download", json={"passphrase": PW})
    assert r.status_code in (404, 422)


def test_rotation_endpoints(client):
    client.post("/api/init", json={"passphrase": PW})
    fid = client.post("/api/files", files={"file": ("a.txt", b"data")}, data={"passphrase": PW}).json()["file_id"]
    assert client.post("/api/rotate/keys", json={"passphrase": PW}).json() == {"files_rewrapped": 1}
    new = "a different passphrase"
    assert client.post("/api/rotate/passphrase", json={"passphrase": PW, "new_passphrase": new}).status_code == 200
    assert client.post(f"/api/files/{fid}/download", json={"passphrase": new}).content == b"data"
    assert client.post(f"/api/files/{fid}/download", json={"passphrase": PW}).status_code == 401


def test_audit_and_security_scan(client, monkeypatch, tmp_path):
    # Uses its own app with a controllable clock so the lockout caused by the bad unlocks can be waited out.
    from tests.conftest import FakeClock

    from securevault.api.main import create_app

    clk = FakeClock()
    c = TestClient(create_app(clock=clk))
    c.post("/api/init", json={"passphrase": PW})
    for _ in range(6):
        c.post("/api/files/list", json={"passphrase": "bad bad bad bad"})
        clk.advance(1)
    audit = c.get("/api/audit").json()
    # Phase 1 change: the 5th failure trips the lockout, so the newest entry can be `lockout`; the 6th
    # request is refused with 429 before it is logged.
    assert audit["ok"] and audit["entries"][0]["event"] in {"unlock_failed", "alert", "lockout"}
    clk.advance(61)  # wait out the 60 s lockout
    # Phase 3 contract change (deliberate): a scan writes alerts into the audit chain, so it now needs
    # the passphrase. It used to be an unauthenticated POST with no body.
    assert c.post("/api/security/scan").status_code == 422
    scan = c.post("/api/security/scan", json={"passphrase": PW}).json()
    assert any(a["rule"] == "failed_unlocks" for a in scan["alerts"])
    assert c.get("/api/audit").json()["ok"]


def test_security_headers_and_index(client):
    r = client.get("/api/status")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"
    assert "default-src 'self'" in r.headers["content-security-policy"]


def test_upload_requires_the_passphrase(client):
    client.post("/api/init", json={"passphrase": PW})
    assert client.post("/api/files", files={"file": ("a.txt", b"x")}).status_code == 422
    wrong = client.post("/api/files", files={"file": ("a.txt", b"x")}, data={"passphrase": "wrong wrong wrong"})
    assert wrong.status_code == 401
    assert client.get("/api/files").json() == []
