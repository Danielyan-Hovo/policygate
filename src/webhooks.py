from __future__ import annotations

import hashlib
import hmac
import time
from collections import deque


class ReplayGuard:
    def __init__(self, ttl_seconds: int = 300, max_entries: int = 10_000) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._seen: dict[str, float] = {}
        self._order: deque[str] = deque()

    def accept(self, delivery_id: str, now: float | None = None) -> bool:
        current = time.time() if now is None else now
        self._purge(current)
        if not delivery_id or delivery_id in self._seen:
            return False
        self._seen[delivery_id] = current
        self._order.append(delivery_id)
        return True

    def _purge(self, now: float) -> None:
        while self._order and (now - self._seen[self._order[0]] > self.ttl_seconds or len(self._order) > self.max_entries):
            expired = self._order.popleft()
            self._seen.pop(expired, None)


def verify_github_signature(body: bytes, secret: str, header: str | None) -> bool:
    if not body or not secret or not header or not header.startswith("sha256="):
        return False
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={digest}", header)


class WebhookHandler:
    def __init__(self, secret: str, guard: ReplayGuard | None = None) -> None:
        self.secret = secret
        self.guard = guard or ReplayGuard()

    def handle(self, delivery_id: str, body: bytes, signature: str | None, timestamp: float | None = None) -> dict[str, object]:
        if not self.guard.accept(delivery_id, now=timestamp):
            return {"accepted": False, "reason": "replay_or_missing_delivery_id"}
        if not verify_github_signature(body, self.secret, signature):
            return {"accepted": False, "reason": "invalid_signature"}
        return {"accepted": True, "delivery_id": delivery_id}
