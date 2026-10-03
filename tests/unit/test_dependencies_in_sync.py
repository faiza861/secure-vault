"""pyproject.toml and requirements.txt must list the same runtime libraries.

Vercel (and `pip install .`) read pyproject.toml; the launcher and docs use requirements.txt. If they drift apart,
a deployment can start without a library the app needs.
"""

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _requirements() -> set[str]:
    names = set()
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line and not line.startswith("-"):
            names.add(line.replace(" ", "").lower())
    return names


def test_pyproject_lists_the_same_runtime_dependencies():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = {d.replace(" ", "").lower() for d in data["project"]["dependencies"]}
    assert declared == _requirements()
