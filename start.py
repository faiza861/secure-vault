"""One-step launcher for Secure Vault (the web app, on your own computer).

What it does, in plain words:
  1. Checks that Python is new enough.
  2. Creates a private Python environment in the ".venv" folder (first run only).
  3. Installs the libraries the app needs (first run only, needs internet).
  4. Creates a ".env" settings file with a fresh random session secret (first run only).
  5. Starts the web app and opens it in your browser.

What it does NOT do: it never changes the app's code, never touches your vault data,
and it only listens on this computer (127.0.0.1), so nobody else on your network can reach it.

Run it with:  python start.py        (Windows: double-click Start-SecureVault.bat)
Options:      --port 8000   --no-browser   --setup-only
"""

# NOTE: this file must be readable by older Python versions too, so it can print a friendly
# "please upgrade Python" message instead of crashing with a syntax error.
from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / ".venv"
REQUIREMENTS = ROOT / "requirements.txt"  # runtime libraries only (no test tools, no ML training libs)
DEPS_MARKER = VENV_DIR / ".securevault-requirements.sha256"
ENV_FILE = ROOT / ".env"
HOST = "127.0.0.1"  # this computer only; deliberately not configurable
DEFAULT_PORT = 8000
MIN_PYTHON = (3, 11)
PORT_TRIES = 20


def say(message: str = "") -> None:
    print(message, flush=True)


def check_python(version: tuple) -> str | None:
    """Return an error message if this Python is too old, otherwise None."""
    if tuple(version[:2]) < MIN_PYTHON:
        return (
            f"Secure Vault needs Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer, "
            f"but this is Python {version[0]}.{version[1]}.\n"
            "Install the latest Python from https://www.python.org/downloads/ "
            "(on Windows, tick 'Add python.exe to PATH'), then run this again."
        )
    return None


def venv_python() -> Path:
    """Path of the Python program inside the private environment."""
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def requirements_fingerprint(path: Path = REQUIREMENTS) -> str:
    """Fingerprint of the requirements file, so we only reinstall when it changes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def find_free_port(preferred: int, tries: int = PORT_TRIES) -> int | None:
    """First port from `preferred` upwards that nothing else is using, or None."""
    for port in range(preferred, preferred + tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind((HOST, port))
            except OSError:
                continue
            return port
    return None


def ensure_env_file(path: Path = ENV_FILE) -> bool:
    """Create a minimal .env with a random SESSION_SECRET if there is none. Returns True if created.

    SECURITY: the secret is generated here with the `secrets` module on this computer, is never printed,
    and stays in a git-ignored file. An existing .env is never modified.
    """
    if path.exists():
        return False
    content = (
        "# Created by start.py. Local settings; never commit this file.\n"
        "STORAGE_BACKEND=local\n"
        "# Signs short-lived login sessions. Keep it private.\n"
        f"SESSION_SECRET={secrets.token_urlsafe(48)}\n"
    )
    path.write_text(content, encoding="utf-8")
    try:
        path.chmod(0o600)  # owner-only where the system supports it (no effect on Windows)
    except OSError:
        pass
    return True


def run_quiet(command: list, what: str) -> None:
    """Run a setup command; on failure show the last lines of its output in plain language."""
    result = subprocess.run(command, cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, check=False)
    if result.returncode != 0:
        tail = "\n".join(result.stdout.strip().splitlines()[-12:])
        raise SystemExit(f"\nSetup step failed: {what}\n\n{tail}\n\nCheck your internet connection and try again.")


def ensure_environment() -> None:
    """Create .venv and install the libraries if needed. Safe to run repeatedly."""
    first_time = not venv_python().exists()
    if first_time:
        say("First start: creating a private Python environment (one time only)...")
        run_quiet([sys.executable, "-m", "venv", str(VENV_DIR)], "creating the .venv folder")
    else:
        probe = subprocess.run([str(venv_python()), "-c", "import sys"], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, check=False)
        if probe.returncode != 0:
            raise SystemExit(
                "The existing '.venv' folder does not work on this computer (it may have been copied from another "
                "one).\nDelete the '.venv' folder and run this again; it will be rebuilt."
            )
    wanted = requirements_fingerprint()
    current = DEPS_MARKER.read_text(encoding="utf-8").strip() if DEPS_MARKER.exists() else ""
    if current != wanted:
        say("Installing the libraries Secure Vault needs. This takes 1-3 minutes the first time...")
        run_quiet([str(venv_python()), "-m", "pip", "install", "--disable-pip-version-check", "-q",
                   "-r", str(REQUIREMENTS)], "installing libraries")
        DEPS_MARKER.write_text(wanted, encoding="utf-8")


def open_browser_when_ready(url: str, timeout: float = 40.0) -> None:
    """Wait until the server answers, then open the page. Runs in a background thread."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url + "/api/status", timeout=2):
                webbrowser.open(url)
                return
        except (urllib.error.URLError, OSError):
            time.sleep(0.5)


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(description="Start Secure Vault on this computer.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="preferred port (default 8000)")
    parser.add_argument("--no-browser", action="store_true", help="do not open the browser automatically")
    parser.add_argument("--setup-only", action="store_true", help="install everything, then stop")
    args = parser.parse_args(argv)

    problem = check_python(sys.version_info)
    if problem:
        say(problem)
        return 1
    if not REQUIREMENTS.exists():
        say("requirements.txt was not found. Run this from the Secure Vault project folder.")
        return 1

    say("Secure Vault launcher")
    say("---------------------")
    ensure_environment()
    if ensure_env_file():
        say("Created a local settings file (.env) with a random session secret.")
    if args.setup_only:
        say("Setup finished. Start the app any time with:  python start.py")
        return 0

    port = find_free_port(args.port)
    if port is None:
        say(f"Could not find a free port near {args.port}. Close other programs or use --port.")
        return 1
    if port != args.port:
        say(f"Port {args.port} is busy, using {port} instead.")
    url = f"http://{HOST}:{port}"

    say("")
    say(f"Secure Vault is starting at  {url}")
    say(f"Your encrypted files are stored in:  {ROOT / 'data' / 'vault'}")
    say("Remember your passphrase: it cannot be recovered. Press Ctrl+C in this window to stop.")
    say("")
    if not args.no_browser:
        threading.Thread(target=open_browser_when_ready, args=(url,), daemon=True).start()

    command = [str(venv_python()), "-m", "uvicorn", "securevault.api.main:app", "--app-dir", "src",
               "--host", HOST, "--port", str(port)]
    try:
        return subprocess.call(command, cwd=str(ROOT))
    except KeyboardInterrupt:
        say("\nStopped. Your vault is saved on disk.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
