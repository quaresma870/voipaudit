"""
Rate limiting — per-module pacing (RateLimiter) plus a hard, session-wide
ceiling (GlobalRateBudget) that no module can exceed regardless of bugs.

Per-module limiters control how *fast* one module sends requests. The
global budget controls the *total* across every module for the entire
engagement session — a module with a bug that turns a bounded probe loop
into an effectively unbounded one still can't exceed it, because every
RateLimiter that's wired to the engagement's shared budget consumes from
it on every single wait() call, not just its own local pacing.
"""

from __future__ import annotations

import threading
import time

DEFAULT_MAX_TOTAL_REQUESTS = 1000
DEFAULT_MAX_PER_SECOND = 10.0
# Deliberately much more conservative than a typical HTTP-scanning
# toolkit's defaults (e.g. redteam-toolkit uses 5000/100.0) — SIP
# probing over UDP against a real PBX can look and feel like a real
# REGISTER/OPTIONS flood at much lower request rates than an HTTP
# scanner would need to cause a problem, since many PBX/SBC
# implementations rate-limit or ban on SIP-layer signal volume alone.


class RateBudgetExceeded(RuntimeError):
    """Raised when a module attempts to exceed the engagement-wide global
    rate budget — this is a hard stop, not a pacing delay."""


class RateLimiter:
    def __init__(self, max_per_second: float, global_budget: GlobalRateBudget | None = None):
        self.max_per_second = max_per_second
        self._min_interval = 1.0 / max_per_second if max_per_second > 0 else 0.0
        self._last_call: float | None = None
        self.global_budget = global_budget

    def wait(self) -> None:
        """Consumes from the global budget (if wired) — raising
        RateBudgetExceeded if the session-wide ceiling is hit — then blocks
        just long enough to keep this module's own call rate at or below
        its configured local ceiling."""
        if self.global_budget is not None:
            self.global_budget.consume()

        if self._min_interval <= 0:
            return
        now = time.monotonic()
        if self._last_call is not None:
            elapsed = now - self._last_call
            if elapsed < self._min_interval:
                time.sleep(self._min_interval - elapsed)
        self._last_call = time.monotonic()


class GlobalRateBudget:
    """A hard ceiling on total requests across an entire engagement
    session. Thread-safe — multiple modules sharing one Engagement (and
    therefore one budget) may run concurrently."""

    def __init__(
        self,
        max_total_requests: int = DEFAULT_MAX_TOTAL_REQUESTS,
        max_per_second: float = DEFAULT_MAX_PER_SECOND,
    ):
        self.max_total_requests = max_total_requests
        self.max_per_second = max_per_second
        self._count = 0
        self._limiter = RateLimiter(max_per_second)  # no nested global_budget — this IS the global one
        self._lock = threading.Lock()

    def consume(self) -> None:
        with self._lock:
            if self._count >= self.max_total_requests:
                raise RateBudgetExceeded(
                    f"Global rate budget exhausted: {self._count}/{self.max_total_requests} "
                    f"requests already made this session. Refusing further requests."
                )
            self._count += 1
        self._limiter.wait()

    @property
    def used(self) -> int:
        return self._count

    @property
    def remaining(self) -> int:
        return max(0, self.max_total_requests - self._count)
