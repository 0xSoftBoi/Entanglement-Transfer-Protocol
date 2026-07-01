"""
WebhookDispatcher — persistent outbox delivery with retries and signing.

Replaces best-effort fire-and-forget threads: events are enqueued as
webhook_outbox rows at emit time (surviving crashes/restarts), and a dispatcher
drains due rows, POSTing each to the tenant's registered URL with an HMAC
signature the receiver can verify:

    X-ETP-Signature: sha3-256=<hex hmac(webhook_secret, body)>

Delivery semantics: at-least-once, ordered per enqueue within a single
dispatcher, exponential backoff (base * 2^attempts) up to max_attempts, then
the row is left undelivered for inspection. Run `run_once()` on a scheduler or
in a loop; it is safe to run repeatedly and after crashes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import urllib.request

from .store import CloudStore

__all__ = ["WebhookDispatcher", "sign_payload"]


def sign_payload(secret: str, body: bytes) -> str:
    """The X-ETP-Signature header value for a payload."""
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha3_256).hexdigest()
    return f"sha3-256={digest}"


class WebhookDispatcher:
    def __init__(self, store: CloudStore, *,
                 max_attempts: int = 8, backoff_base: float = 30.0,
                 timeout: float = 5.0) -> None:
        self._store = store
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base
        self._timeout = timeout

    def run_once(self, now: float | None = None) -> dict:
        """Deliver all due events; returns {'delivered': n, 'failed': n}."""
        delivered = failed = 0
        for row in self._store.due_events(max_attempts=self._max_attempts, now=now):
            tenant = self._store.tenant(row["tenant_id"])
            url = tenant and tenant.get("webhook_url")
            if not url:
                # Tenant removed their webhook — retire the event as delivered.
                self._store.mark_event_delivered(row["id"])
                continue
            if self._deliver(url, tenant.get("webhook_secret") or "", row["event"]):
                self._store.mark_event_delivered(row["id"])
                delivered += 1
            else:
                retry_in = self._backoff_base * (2 ** row["attempts"])
                self._store.mark_event_failed(row["id"], retry_in)
                failed += 1
        return {"delivered": delivered, "failed": failed}

    def _deliver(self, url: str, secret: str, event: dict) -> bool:
        body = json.dumps(event).encode("utf-8")
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-ETP-Signature", sign_payload(secret, body))
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return 200 <= resp.status < 300
        except Exception:
            return False
