"""
Billing export — metered usage in Stripe-shaped records.

The billable unit is a notarized capture (idempotent submits are never
double-counted, enforced at the service layer). Each export computes, per
tenant, the delta since the last snapshot and emits one JSONL record shaped for
Stripe metered billing, then records the new snapshot — so exports are
incremental and re-runnable (a tenant with no new captures produces no record).

    run_billing_export(store, "usage-2026-07.jsonl")

Pushing records to the Stripe API is deliberately one function away: iterate
the JSONL and call the usage-record endpoint once the Stripe connector is
authorized (see ONE_SHOT_PLAN scope decision #2).
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from .store import CloudStore

__all__ = ["usage_deltas", "run_billing_export"]


def usage_deltas(store: CloudStore) -> list[dict]:
    """Per-tenant billable deltas since the last snapshot (zero deltas omitted)."""
    plans = store.tenant_plans()
    now = time.time()
    out = []
    for tenant_id, total in sorted(store.usage_by_tenant().items()):
        last = store.last_billing_snapshot(tenant_id)
        delta = total - last
        if delta <= 0:
            continue
        out.append({
            "tenant_id": tenant_id,
            "plan": plans.get(tenant_id, "free"),
            "quantity": delta,
            "timestamp": int(now),
            # Stripe usage-record idempotency: stable for a given (tenant, range).
            "idempotency_key": f"{tenant_id}:{last}:{total}",
        })
    return out


def run_billing_export(store: CloudStore, path: str | Path) -> list[dict]:
    """Write the current deltas as JSONL and snapshot them. Returns the records."""
    records = usage_deltas(store)
    with open(path, "a") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    for r in records:
        store.record_billing_snapshot(r["tenant_id"], r["quantity"] +
                                      store.last_billing_snapshot(r["tenant_id"]))
    return records
