"""
Background worker entrypoint — anchoring + webhook delivery on an interval.

    export ETP_CLOUD_DB=postgresql://…            # or a sqlite path
    export ETP_CLOUD_WORKER_INTERVAL=600          # seconds (default 10 min)
    # AnchorClient config (only if anchoring is enabled):
    export GSX_RPC_URL=… GSX_DEPLOYER_KEY=… ANCHOR_CONTRACT=…
    python -m ltp.cloud.worker

Runs, per tick: AnchorWorker.run_once() (enqueue → submit → reconcile) when an
AnchorClient can be constructed from the environment, and always
WebhookDispatcher.run_once(). Every stage is idempotent, so overlapping or
restarted workers are safe; production should still run a single instance
(advisory lock) to avoid wasted RPC calls.
"""

from __future__ import annotations

import os
import time

from .store import open_store
from .webhooks import WebhookDispatcher
from .anchoring import AnchorWorker

__all__ = ["main"]


def _try_anchor_client():
    """Build the real AnchorClient from env; None if unconfigured/uninstalled."""
    try:
        from ..anchor.client import AnchorClient
        return AnchorClient.from_env()
    except Exception as e:
        print(f"anchoring disabled ({type(e).__name__}: {e}) — running outbox only")
        return None


def main() -> int:
    store = open_store(os.environ.get("ETP_CLOUD_DB", "custody-cloud.db"))
    interval = float(os.environ.get("ETP_CLOUD_WORKER_INTERVAL", "600"))
    operator = store.get_or_create_operator()
    dispatcher = WebhookDispatcher(store)
    client = _try_anchor_client()
    worker = AnchorWorker(store, client, operator.vk) if client else None

    print(f"etp-custody-worker: interval={interval}s anchoring={'on' if worker else 'off'}")
    while True:
        if worker is not None:
            stats = worker.run_once()
            if any(stats.values()):
                print(f"anchor: {stats}")
        delivered = dispatcher.run_once()
        if any(delivered.values()):
            print(f"webhooks: {delivered}")
        time.sleep(interval)


if __name__ == "__main__":
    raise SystemExit(main())
