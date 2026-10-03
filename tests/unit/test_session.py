"""Session tokens: signing, tamper detection, expiry, recent-MFA logic. Pure functions."""

import pytest

from securevault.security import session as sess
from securevault.utils.exceptions import SessionExpired, SessionInvalid

KEY = b"k" * 32
POL = sess.SessionPolicy(ttl_seconds=900, idle_seconds=300, reauth_window_seconds=300)
T0 = 1_000_000.0


def mk(mfa=True):
    return sess.new_claims(T0, POL, mfa_verified=mfa)


def test_roundtrip_and_no_secret_material_in_token():
    token = sess.encode(KEY, mk())
    claims = sess.decode(KEY, token)
    assert claims.mf is True and len(claims.sid) == 32
    import base64

    payload = base64.urlsafe_b64decode(token.split(".")[1] + "==").decode()
    assert set(__import__("json").loads(payload)) == {"sid", "iat", "exp", "act", "ra", "mf"}  # claims only


@pytest.mark.parametrize("mangle", [
    lambda t: t[:-2] + ("AA" if not t.endswith("AA") else "BB"),  # bad signature
    lambda t: t.replace("v1.", "v2.", 1),
    lambda t: t.rsplit(".", 1)[0],  # signature removed
    lambda t: "",
    lambda t: "a.b.c",
    lambda t: t + "x" * 1000,  # oversize
])
def test_tampered_or_malformed_tokens_are_invalid(mangle):
    with pytest.raises(SessionInvalid):
        sess.decode(KEY, mangle(sess.encode(KEY, mk())))


def test_wrong_key_is_invalid():
    with pytest.raises(SessionInvalid):
        sess.decode(b"x" * 32, sess.encode(KEY, mk()))


def test_payload_swap_is_detected():
    a, b = sess.encode(KEY, mk()), sess.encode(KEY, mk(mfa=False))
    forged = ".".join([a.split(".")[0], b.split(".")[1], a.split(".")[2]])
    with pytest.raises(SessionInvalid):
        sess.decode(KEY, forged)


def test_expiry_rules():
    c = mk()
    sess.check_active(c, T0 + 299, POL)
    with pytest.raises(SessionExpired) as idle:
        sess.check_active(c, T0 + 300, POL)  # inactivity
    assert idle.value.reason == "idle"
    kept = sess.touch(c, T0 + 800, reauthenticated=False)
    with pytest.raises(SessionExpired) as absolute:
        sess.check_active(kept, T0 + 900, POL)  # absolute lifetime wins even if active
    assert absolute.value.reason == "absolute"
    with pytest.raises(SessionInvalid):
        sess.check_active(sess.SessionClaims("a" * 32, T0 + 999, T0 + 5000, T0, T0, True), T0, POL)  # from the future


def test_recent_mfa_window_and_no_upgrade_from_passphrase_only():
    c = mk()
    assert sess.is_recent_mfa(c, T0 + 300, POL) and not sess.is_recent_mfa(c, T0 + 301, POL)
    assert not sess.is_recent_mfa(mk(mfa=False), T0, POL)  # a session without a verified code never counts
    touched = sess.touch(c, T0 + 100)  # activity alone does not extend the auth time
    assert touched.ra == T0 and touched.act == T0 + 100
    re = sess.touch(c, T0 + 400, reauthenticated=True, mfa_verified=True)
    assert re.ra == T0 + 400 and sess.is_recent_mfa(re, T0 + 500, POL)
    assert not sess.touch(c, T0 + 400, reauthenticated=True, mfa_verified=False).mf


def test_secret_selection(monkeypatch):
    class S:
        session_secret = "s" * 40

    assert sess.secret_from_settings(S) == b"s" * 40
    S.session_secret = "short"
    warned = []
    a = sess.secret_from_settings(S, warn=warned.append)
    assert len(a) == 32 and a == sess.secret_from_settings(S) and a != b"short"


def test_fingerprint_does_not_reveal_sid():
    assert "abc" not in sess.sid_fingerprint("abc") and len(sess.sid_fingerprint("abc")) == 16
