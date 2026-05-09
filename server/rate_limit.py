from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass(slots=True)
class RateLimitResult:
    allowed: bool
    retry_after_seconds: int | None = None


class SlidingWindowRateLimiter:
    """Simple in-memory sliding-window rate limiter.

    This is intentionally basic for a course project. It is enough to demonstrate
    abuse control against brute-force login attempts and friend-request spam.
    """

    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window_seconds: int) -> RateLimitResult:
        now = time.monotonic()
        threshold = now - window_seconds
        with self._lock:
            queue = self._events[key]
            while queue and queue[0] < threshold:
                queue.popleft()
            if len(queue) >= limit:
                retry_after = max(1, int(window_seconds - (now - queue[0])))
                return RateLimitResult(allowed=False, retry_after_seconds=retry_after)
            queue.append(now)
            return RateLimitResult(allowed=True, retry_after_seconds=None)
