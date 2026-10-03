"""Pure lockout logic: no I/O, `now` injected."""

from securevault.security.lockout import LockoutPolicy, check_lockout, lockout_duration

POLICY = LockoutPolicy()  # 5 failures / 300 s, 60 s first lockout, global 20, cap 900 s
T0 = 1_000_000.0


def fails(n, actor="api:1.2.3.4", start=T0, gap=1.0, event="unlock_failed"):
    return [{"event": event, "actor": actor, "ts": start + i * gap, "details": {}} for i in range(n)]


def test_below_limit_is_allowed():
    assert check_lockout(fails(4), T0 + 5, "api:1.2.3.4", POLICY).allowed


def test_exactly_at_limit_triggers_lockout():
    d = check_lockout(fails(5), T0 + 5, "api:1.2.3.4", POLICY)
    assert not d.allowed and d.scope == "actor" and d.duration == 60
    assert d.retry_after == 60 - 1  # last failure at T0+4, asked at T0+5
    assert d.started_at == T0 + 4


def test_lockout_ends_and_counter_restarts():
    e = fails(5)
    last = T0 + 4
    assert not check_lockout(e, last + 59, "api:1.2.3.4", POLICY).allowed
    assert check_lockout(e, last + 60, "api:1.2.3.4", POLICY).allowed  # exactly at expiry
    # recovery: the failures that caused the lockout are used up, so 4 new ones do not re-lock
    e2 = e + fails(4, start=last + 100)
    assert check_lockout(e2, last + 110, "api:1.2.3.4", POLICY).allowed


def test_window_expiry():
    spread = fails(5, gap=100.0)  # 5 failures spread over 400 s: never 5 inside one 300 s window
    assert check_lockout(spread, T0 + 401, "api:1.2.3.4", POLICY).allowed
    edge = fails(4) + [{"event": "unlock_failed", "actor": "api:1.2.3.4", "ts": T0 + 300, "details": {}}]
    assert check_lockout(edge, T0 + 301, "api:1.2.3.4", POLICY).allowed  # failure at T0 aged out exactly


def test_progressive_backoff_and_cap():
    assert [lockout_duration(n, POLICY) for n in range(4)] == [60, 300, 900, 900]
    e, t = [], T0
    expected = [60, 300, 900]
    for want in expected:
        e += fails(5, start=t)
        d = check_lockout(e, t + 5, "api:1.2.3.4", POLICY)
        assert not d.allowed and d.duration == want
        t += want + 10  # wait the lockout out, then fail again
    assert check_lockout(e, t, "api:1.2.3.4", POLICY).allowed  # never permanent


def test_escalation_forgotten_after_horizon():
    e = fails(5)
    later = T0 + POLICY.escalation_horizon + 1000
    e += fails(5, start=later)
    d = check_lockout(e, later + 5, "api:1.2.3.4", POLICY)
    assert d.duration == 60  # first-offence length again


def test_per_actor_isolation_and_global_backstop():
    other = fails(5, actor="api:9.9.9.9")
    assert check_lockout(other, T0 + 5, "api:1.2.3.4", POLICY).allowed  # someone else's failures
    assert not check_lockout(other, T0 + 5, "api:9.9.9.9", POLICY).allowed
    # 20 failures spread across 20 different actors: nobody hits 5, but the global limit fires for all
    many = [
        {"event": "unlock_failed", "actor": f"api:10.0.0.{i}", "ts": T0 + i, "details": {}} for i in range(20)
    ]
    d = check_lockout(many, T0 + 21, "api:1.2.3.4", POLICY)
    assert not d.allowed and d.scope == "global"


def test_mfa_failures_count_and_other_events_do_not():
    mixed = fails(3) + fails(2, start=T0 + 3, event="mfa_failed")
    assert not check_lockout(mixed, T0 + 6, "api:1.2.3.4", POLICY).allowed
    noise = [{"event": e, "actor": "api:1.2.3.4", "ts": T0, "details": {}} for e in ("unlock", "upload", "alert")] * 10
    assert check_lockout(noise, T0 + 1, "api:1.2.3.4", POLICY).allowed


def test_success_does_not_reset_the_counter():
    # A correct passphrase between TOTP guesses must not give an attacker unlimited guesses.
    e = []
    for i in range(5):
        e.append({"event": "unlock", "actor": "api:1.2.3.4", "ts": T0 + i * 2, "details": {}})
        e.append({"event": "mfa_failed", "actor": "api:1.2.3.4", "ts": T0 + i * 2 + 1, "details": {}})
    assert not check_lockout(e, T0 + 12, "api:1.2.3.4", POLICY).allowed


def test_malformed_entries_are_ignored():
    junk = [{"event": "unlock_failed"}, {"actor": "x"}, {"event": "unlock_failed", "actor": "a", "ts": "nope"}]
    assert check_lockout(junk + fails(2), T0 + 3, "api:1.2.3.4", POLICY).allowed
