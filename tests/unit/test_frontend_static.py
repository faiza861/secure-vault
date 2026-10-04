"""Static guarantees about the web UI: CSP-safe markup, no unsafe DOM writes, theme + contrast."""

import re
from pathlib import Path

import pytest

WEB = Path(__file__).resolve().parents[2] / "web"
HTML = (WEB / "index.html").read_text(encoding="utf-8")
JS = (WEB / "app.js").read_text(encoding="utf-8")
THEME = (WEB / "theme.js").read_text(encoding="utf-8")
CSS = (WEB / "style.css").read_text(encoding="utf-8")


def test_no_inline_script_style_or_handlers():
    assert not re.search(r"<script(?![^>]*\bsrc=)", HTML), "inline <script> would break the CSP"
    assert "<style" not in HTML and not re.search(r'\sstyle="', HTML)
    assert not re.search(r"\son[a-z]+\s*=", HTML), "inline event handler found"
    assert "javascript:" not in HTML.lower()


def test_no_external_resources():
    for text in (HTML, CSS, JS, THEME):
        assert not re.search(r"(?:src|href)=\"https?://", text)
        assert "@import" not in text and "//cdn" not in text and "fonts.googleapis" not in text
    assert not re.search(r"url\(\s*['\"]?https?:", CSS)


def test_theme_script_is_blocking_in_head():
    head = HTML.split("</head>")[0]
    tag = re.search(r"<script[^>]*theme\.js[^>]*>", head)
    assert tag and "defer" not in tag.group(0) and "async" not in tag.group(0)
    assert HTML.index("theme.js") < HTML.index("style.css") or "theme.js" in head


def test_no_unsafe_dom_writes_or_storage_of_secrets():
    for text in (JS, THEME):
        assert not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function", text)
    assert "localStorage" not in JS and "sessionStorage" not in JS and "document.cookie" not in JS
    assert "console." not in JS  # nothing is logged, so no passphrase or token can leak there
    # theme.js stores only the theme choice
    assert re.findall(r"localStorage\.\w+\(([^)]*)\)", THEME) and "passphrase" not in THEME
    assert "location.search" not in JS and "location.hash" not in JS  # nothing read from or written to the URL


def test_theme_css_structure():
    assert re.search(r':root\[data-theme="dark"\]\s*\{', CSS)
    assert re.search(r"@media \(prefers-color-scheme:dark\)\{:root:not\(\[data-theme\]\)", CSS)
    assert len(re.findall(r"\{color-scheme:dark;", CSS)) == 2 and "color-scheme:light" in CSS
    assert "transition:all" not in CSS.replace(" ", "")
    assert "prefers-reduced-motion:reduce" in CSS.replace(" ", "")
    assert "theme-ready" in THEME and "theme-ready" in CSS


def test_required_ui_pieces_exist():
    for needle in ('id="unlock-dlg"', 'id="code-dlg"', 'id="posture"', 'id="access-protection"', 'id="mfa-card"',
                   'autocomplete="one-time-code"', 'inputmode="numeric"', 'maxlength="6"', 'role="status"',
                   'id="reauth-btn"', 'id="signout-btn"', 'id="demo-banner"', 'data-theme-choice="system"', 'name="theme-color"'):
        assert needle in HTML, needle
    assert (WEB / "logo.svg").exists() and "<script" not in (WEB / "logo.svg").read_text().lower()
    assert "http" not in re.sub(r'xmlns="http://www.w3.org/2000/svg"', "", (WEB / "logo.svg").read_text())
    labels = set(re.findall(r'<label[^>]*for="([^"]+)"', HTML))
    for field in ("unlock-pass", "unlock-code", "code-input", "mfa-confirm-code", "init-pass"):
        assert field in labels, f"{field} has no label"


# ---------------------------------------------------------------- WCAG AA contrast of the real tokens


def _tokens(block: str) -> dict[str, str]:
    return dict(re.findall(r"--([a-z-]+):(#[0-9a-fA-F]{3,6})", block))


def _lum(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    h = "".join(c * 2 for c in h) if len(h) == 3 else h
    r, g, b = (int(h[i : i + 2], 16) / 255 for i in (0, 2, 4))
    f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def _ratio(a: str, b: str) -> float:
    hi, lo = sorted((_lum(a), _lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


LIGHT = _tokens(re.search(r"^:root\{(.*?)\}", CSS, re.DOTALL | re.MULTILINE).group(1))
DARK = _tokens(re.search(r':root\[data-theme="dark"\]\{(.*?)\}', CSS, re.DOTALL).group(1))
SYSTEM_DARK = _tokens(re.search(r":root:not\(\[data-theme\]\)\{(.*?)\}\}", CSS, re.DOTALL).group(1))

TEXT = [("ink", "bg"), ("ink", "card"), ("muted", "card"), ("muted", "bg"), ("accent-ink", "accent"), ("cl", "cl-bg"),
        ("pq", "pq-bg"), ("ai", "ai-bg"), ("ok", "ok-bg"), ("bad", "bad-bg"), ("bad", "card"), ("warn-ink", "warn-bg"),
        ("ink", "cl-bg")]
UI = [("field", "card"), ("field", "bg"), ("warn-line", "bg"), ("bad", "bg"), ("accent", "card"), ("pq", "card")]


@pytest.mark.parametrize("name", ["LIGHT", "DARK"])
def test_wcag_aa_contrast(name):
    theme = {"LIGHT": LIGHT, "DARK": {**LIGHT, **DARK}}[name]
    for fg, bg in TEXT:
        assert _ratio(theme[fg], theme[bg]) >= 4.5, (name, fg, bg, _ratio(theme[fg], theme[bg]))
    for fg, bg in UI:
        assert _ratio(theme[fg], theme[bg]) >= 3.0, (name, fg, bg, _ratio(theme[fg], theme[bg]))


def test_system_dark_matches_explicit_dark():
    assert SYSTEM_DARK == DARK  # the two dark blocks must never drift apart
