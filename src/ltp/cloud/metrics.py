"""
Prometheus metrics for the custody service — hand-rolled text exposition
(format v0.0.4), no client library. Everything derives from store queries, so
the endpoint is correct after crashes/restarts with zero in-process state.
Exposed as GET /metrics on both HTTP layers.
"""

from __future__ import annotations

from .store import CloudStore

__all__ = ["render_metrics"]


def _esc(label: str) -> str:
    return label.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render_metrics(store: CloudStore) -> str:
    lines: list[str] = []

    def metric(name: str, mtype: str, help_: str, samples: list[tuple[dict, float]]):
        lines.append(f"# HELP {name} {help_}")
        lines.append(f"# TYPE {name} {mtype}")
        for labels, value in samples:
            lbl = ",".join(f'{k}="{_esc(str(v))}"' for k, v in labels.items())
            lines.append(f"{name}{{{lbl}}} {value}" if lbl else f"{name} {value}")

    metric("etp_tenants_total", "gauge", "Number of tenants",
           [({}, len(store.tenant_ids()))])
    metric("etp_captures_total", "counter", "Notarized captures (the billable unit)",
           [({}, store.total_captures())])
    metric("etp_captures", "counter", "Notarized captures per tenant",
           [({"tenant": t}, n) for t, n in sorted(store.usage_by_tenant().items())])
    metric("etp_anchors", "gauge", "Anchor rows by lifecycle status",
           [({"status": s}, n) for s, n in sorted(store.anchor_status_counts().items())])
    metric("etp_webhook_outbox_pending", "gauge", "Undelivered webhook events",
           [({}, store.outbox_pending())])
    return "\n".join(lines) + "\n"
