import pytest
from typer.testing import CliRunner

from securevault.cli.main import app
from securevault.config import get_settings

runner = CliRunner()
PW = "cli test passphrase"


@pytest.fixture
def cli_env(tmp_path, monkeypatch):
    monkeypatch.setenv("STORAGE_BACKEND", "local")
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "vault"))
    monkeypatch.setenv("SECUREVAULT_PASSPHRASE", PW)
    monkeypatch.setenv("MODEL_PATH", str(tmp_path / "no-model.json"))
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


def run(*args, input=None):
    return runner.invoke(app, list(args), input=input)


def test_cli_end_to_end(cli_env):
    assert "not initialised" in run("status").output
    assert run("init", input=f"{PW}\n{PW}\n").exit_code == 0
    secret = cli_env / "plan.txt"
    secret.write_bytes(b"attack at dawn")
    up = run("upload", str(secret))
    assert up.exit_code == 0
    file_id = up.output.split(" as ")[1].strip()

    listing = run("list").output
    assert file_id in listing and "plan.txt" in listing

    out = cli_env / "out"
    dl = run("download", file_id, "-o", str(out))
    assert dl.exit_code == 0 and (out / "plan.txt").read_bytes() == b"attack at dawn"
    assert run("download", file_id, "-o", str(out)).exit_code == 1  # refuses to overwrite
    assert run("download", file_id, "-o", str(out), "--force").exit_code == 0

    assert run("rotate-keys").exit_code == 0
    assert run("verify").exit_code == 0
    assert "INTACT" in run("audit").output
    assert "Scanned" in run("scan").output
    assert run("delete", file_id).exit_code == 0


def test_cli_wrong_passphrase_fails(cli_env, monkeypatch):
    run("init", input=f"{PW}\n{PW}\n")
    monkeypatch.setenv("SECUREVAULT_PASSPHRASE", "this is wrong!!")
    result = run("list")
    assert result.exit_code == 1 and "wrong passphrase" in result.output


def test_cli_detects_tampered_audit_log(cli_env):
    run("init", input=f"{PW}\n{PW}\n")
    f = cli_env / "a.txt"
    f.write_bytes(b"x")
    run("upload", str(f))
    log = cli_env / "vault" / "audit.jsonl"
    log.write_text(log.read_text().replace('"bytes":1', '"bytes":9'))
    result = run("verify")
    assert result.exit_code == 1 and "TAMPERED" in result.output
