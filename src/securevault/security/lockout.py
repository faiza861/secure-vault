"""Progressive rate limiting and temporary lockout, derived from the audit log.

SECURITY DESIGN
* STATELESS: nothing lives in process memory. The state is *recomputed* from the audit
  entries that are passed in, so it survives restarts and works on serverless hosts
  (Vercel) where every request may run in a fresh instance. No Redis, no counters.
* PURE: no I/O, no clock. `now` is injected, so the whole thing is deterministic to test.
* The failures it counts are the `unlock_failed` and `mfa_failed` events that the Vault
  already writes into the hash-chained log. An attacker cannot delete them without
  breaking the chain.
* Two scopes are enforced together: PER ACTOR (the client address) and a GLOBAL backstop
  across all actors. The global limit is what still protects the vault when the real
  client address is hidden behind a proxy (we deliberately do not trust X-Forwarded-For,
  because a client can forge it to dodge the per-actor limit).
* PROGRESSIVE: the 1st lockout lasts `lockout_seconds` (60 s), each further lockout inside
  the escalation horizon is 5x longer (300 s, then the cap), never longer than
  `lockout_max_seconds` (900 s). The cap means the owner is never locked out permanently.
* A lockout "consumes" the failures that caused it, so once it expires the counter starts
  from zero again (recovery after restriction).
* Successful authentication deliberately does NOT reset the counter. Otherwise an attacker
  who already knows the passphrase could log in successfully between guesses and brute-force
  the TOTP code without limit.
* Best-effort limits: two requests that arrive at the same instant can both pass the check
  before either failure is written, so the limit can be overshot by a few attempts.
"""

import math
from collections import deque
from dataclasses import dataclass

FAILURE_EVENTS = frozenset({"unlock_failed", "mfa_failed"})
LOCKOUT_GROWTH = 5  # 60 s -> 300 s -> (1500 s, capped to 900 s)
_MAX_LEVEL = 8  # keeps 5**level small; the cap is reached long before this


@dataclass(frozen=True)
class LockoutPolicy:
    max_failures: int = 5  # failures per actor inside the window that trigger a lockout
    window_seconds: int = 300
    lockout_seconds: int = 60  # first lockout length
    global_max_failures: int = 20  # backstop across all actors
    lockout_max_seconds: int = 900  # hard cap: the owner is never locked out for good

    @property
    def escalation_horizon(self) -> int:
        """Earlier lockouts older than this no longer make the next one longer."""
        return self.lockout_max_seconds * 4

    def to_public_dict(self) -> dict:
        """Non-secret numbers only; safe to show in /api/status."""
        return {
            "max_failures": self.max_failures,
            "window_seconds": self.window_seconds,
            "lockout_seconds": self.lockout_seconds,
            "lockout_max_seconds": self.lockout_max_seconds,
        }


@dataclass(frozen=True)
class LockoutDecision:
    allowed: bool
    retry_after: int = 0  # whole seconds, >= 1 whenever allowed is False
    scope: str | None = None  # "actor" or "global": which limit is active
    started_at: float | None = None  # when the active lockout began (its triggering failure)
    duration: int | None = None


def policy_from_settings(settings) -> LockoutPolicy:
    return LockoutPolicy(
        max_failures=settings.rate_limit_max_failures,
        window_seconds=settings.rate_limit_window_seconds,
        lockout_seconds=settings.lockout_seconds,
        global_max_failures=settings.rate_limit_global_max_failures,
        lockout_max_seconds=settings.lockout_max_seconds,
    )


def lockout_duration(prior_lockouts: int, policy: LockoutPolicy) -> int:
    """Progressive length: base * 5**n, never above the hard cap."""
    level = min(prior_lockouts, _MAX_LEVEL)
    return min(policy.lockout_max_seconds, policy.lockout_seconds * LOCKOUT_GROWTH**level)


def _replay(
    times: list[float], limit: int, policy: LockoutPolicy, now: float | None = None
) -> tuple[float, float, int, int]:
    """Replay failure times in order. Returns (locked_until, started_at, duration, in_window) for the
    most recent lockout ((0, 0, 0, ...) if none), where in_window is how many counted failures are
    still inside the sliding window at `now` (only computed when `now` is given)."""
    window: deque[float] = deque()
    triggers: deque[float] = deque()
    until = started = 0.0
    duration = 0
    for t in times:
        if t < until:  # a racing request that slipped in during a lockout: ignore it
            continue
        while window and window[0] <= t - policy.window_seconds:  # sliding window; edge expires
            window.popleft()
        window.append(t)
        if len(window) >= limit:
            while triggers and triggers[0] <= t - policy.escalation_horizon:
                triggers.popleft()
            duration = lockout_duration(len(triggers), policy)
            until, started = t + duration, t
            triggers.append(t)
            window.clear()  # these failures are now "used up" by the lockout
    in_window = sum(1 for t in window if now is not None and t > now - policy.window_seconds)
    return until, started, duration, in_window


def check_lockout(entries: list[dict], now: float, actor: str, policy: LockoutPolicy) -> LockoutDecision:
    """Decide whether an authentication attempt may proceed right now.

    `entries` are audit entries in ascending order (a recent tail is enough). Only
    `unlock_failed` / `mfa_failed` events are looked at. Malformed entries are skipped.
    """
    mine: list[float] = []
    everyone: list[float] = []
    for e in entries:
        try:
            if e["event"] not in FAILURE_EVENTS:
                continue
            ts = float(e["ts"])
            everyone.append(ts)
            if e["actor"] == actor:
                mine.append(ts)
        except (KeyError, TypeError, ValueError):
            continue

    best = LockoutDecision(True)
    for scope, times, limit in (
        ("actor", mine, policy.max_failures),
        ("global", everyone, policy.global_max_failures),
    ):
        until, started, duration, _ = _replay(times, limit, policy, now)
        if now < until:
            retry = max(1, math.ceil(until - now))
            if retry > best.retry_after:
                best = LockoutDecision(False, retry, scope, started, duration)
    return best


def failures_in_window(entries: list[dict], now: float, actor: str, policy: LockoutPolicy) -> int:
    """How many counted failures this actor currently has toward the next lockout (for the UI)."""
    times = []
    for e in entries:
        try:
            if e["event"] in FAILURE_EVENTS and e["actor"] == actor:
                times.append(float(e["ts"]))
        except (KeyError, TypeError, ValueError):
            continue
    return _replay(times, policy.max_failures, policy, now)[3]
