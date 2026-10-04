"""The one-step launcher (start.py): only its safe, pure helpers are tested here. Nothing is installed or started."""

import socket

import start


def test_old_python_gets_a_friendly_message():
    message = start.check_python((3, 10, 9))
    assert message and "3.11" in message and "Install" in message
    assert start.check_python((3, 11, 0)) is None
    assert start.check_python((3, 13, 1)) is None


def test_find_free_port_skips_a_busy_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as busy:
        busy.bind((start.HOST, 0))
        taken = busy.getsockname()[1]
        found = start.find_free_port(taken)
        assert found is not None and found != taken


def test_env_file_is_created_once_with_a_random_secret(tmp_path):
    target = tmp_path / ".env"
    assert start.ensure_env_file(target) is True
    text = target.read_text(encoding="utf-8")
    secret = next(line.split("=", 1)[1] for line in text.splitlines() if line.startswith("SESSION_SECRET="))
    assert len(secret) >= 32 and "STORAGE_BACKEND=local" in text

    # a second run must never overwrite what is already there (the user may have edited it)
    target.write_text("SESSION_SECRET=mine\n", encoding="utf-8")
    assert start.ensure_env_file(target) is False
    assert target.read_text(encoding="utf-8") == "SESSION_SECRET=mine\n"


def test_two_installs_get_different_secrets(tmp_path):
    first, second = tmp_path / "a.env", tmp_path / "b.env"
    start.ensure_env_file(first)
    start.ensure_env_file(second)
    assert first.read_text() != second.read_text()


def test_requirements_fingerprint_changes_with_the_file(tmp_path):
    reqs = tmp_path / "requirements.txt"
    reqs.write_text("fastapi\n", encoding="utf-8")
    before = start.requirements_fingerprint(reqs)
    assert before == start.requirements_fingerprint(reqs)
    reqs.write_text("fastapi\nuvicorn\n", encoding="utf-8")
    assert start.requirements_fingerprint(reqs) != before


def test_launcher_listens_on_this_computer_only():
    assert start.HOST == "127.0.0.1"
