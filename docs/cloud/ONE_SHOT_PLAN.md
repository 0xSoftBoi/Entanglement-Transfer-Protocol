# One-Shot Plan — Finishing Everything Autonomous in a Single Pass

> **Status: EXECUTED.** All ten items shipped in three commits on
> `claude/satellite-cubesat-scope-7w6o7t` (backend batch → console/cast →
> launch drafts + docs sync), suite green throughout. The parked list at the
> bottom is still the live blocked-on-you inventory.

Scope: every remaining item from `EXECUTION_PLAN.md` that needs nothing from
the user, executed in one continuous run, ending with a green suite and 2–3
clean commits on the working branch. Items blocked on the user stay parked
(listed at the bottom, unchanged).

## Scope decisions (made now, so the run doesn't stall)

1. **Console = static, not Next.js (v1).** C2–C3 ship as `website/console.html`
   (+ shared JS), served from the same static site as `/verify`: API-key login
   (stored in localStorage, never sent anywhere but the notary), dashboard /
   captures / anchors / keys views over the existing API. Rationale: zero build
   step, one-shot-able with high confidence, consistent with the repo's
   zero-dep ethos, deployable to any static host. Next.js + OAuth (the design
   doc's C2) becomes a post-user-creds upgrade, not a blocker.
2. **Stripe = export, not push.** D1 ships as `cloud/billing.py`: per-tenant
   usage snapshots + a Stripe-metered-billing-shaped export (JSONL) and plan
   gating. The actual API push is one function away once the Stripe connector
   is authorized.
3. **KMS (E1) is deferred entirely** — it needs a cloud account to mean
   anything. The operator-key seam already exists (`get_or_create_operator`).
4. **Compliance pack (E4) ships vertical-agnostic**: an `audit-report`
   generator producing an evidence bundle (log summary, STH chain +
   consistency verification, anchor lifecycle with tx refs) as JSON + Markdown.
   The 21-CFR-11/NERC-CIP framing layers on once a design partner picks the
   vertical.

## Execution order (fail-fast: risky/testable first, artifacts last)

| # | Item | Plan ref | Builds | Test |
|---|---|---|---|---|
| 1 | **Metrics endpoint** — `GET /metrics`, Prometheus text format, hand-rolled (no client lib): captures/anchors-by-status/outbox backlog/usage per tenant; wired into both HTTP layers | B5 | `cloud/metrics.py` | scrape + assert exposition format |
| 2 | **Plan gating** — `tenants.plan` respected: AnchorWorker anchors only `verified` tenants; admin endpoint sets plan | D2 | worker + store + API touch | gated vs ungated tenant |
| 3 | **batchAnchor aggregation** — worker submits >1 pending anchors via `client.batch_anchor()` in one tx | E2 | `anchoring.py` | fake client sees one batch call |
| 4 | **Witness cosigning** — independent keypair countersigns STHs; cosignature verify helper + service endpoint | E3 | `cloud/witness.py` | cosign/verify + forged-witness reject |
| 5 | **Billing export** — usage snapshots table + Stripe-shaped JSONL export + `plan` in admin API | D1′ | `cloud/billing.py` | snapshot idempotency + export shape |
| 6 | **Audit report** — evidence bundle generator (JSON + MD): tenant summary, STH chain w/ append-only verification, anchors | E4′ | `cloud/report.py` | bundle correctness on a seeded tenant |
| 7 | **Static console** — login (API key), dashboard (usage, latest STH), captures table, anchors timeline w/ status chips, key display; graceful errors | C2–C3′ | `website/console.html` (+ js) | headless render + node-driven API smoke |
| 8 | **Demo cast** — synthesize an asciinema v2 `.cast` from the real demo run; link in README | A3 | `website/demo.cast` | plays under `asciinema`-format check (JSON lines) |
| 9 | **Launch drafts** — Show HN post, NLnet/NGI Zero application, SBIR one-pager, awesome-lists blurbs | F1/F2/F5/F3 | `docs/launch/*.md` | n/a (prose) |
| 10 | **Docs sync** — EXECUTION_PLAN ticks, design-doc component table, README console/verify links | — | docs | n/a |

Single full-suite run after #6 (backend complete), again at the end.
**Commits:** (1) backend: metrics+gating+batch+witness+billing+report,
(2) console+cast+README, (3) launch drafts+docs. Push after each.

## Definition of done

- Suite green (≥1,542 passing, 0 failures), new tests for items 1–6.
- Console + verify pages render (headless Chromium screenshots).
- Every EXECUTION_PLAN autonomous row ticked or explicitly re-parked.
- No new required dependencies (metrics/billing/report/witness are stdlib;
  console is static).

## Parked (blocked on you — unchanged)

Vercel deploy (A2/C4) · GSX RPC + funded key for the real-chain anchor (A4) ·
Stripe connector auth for live push (D1) · OAuth creds for the Next.js console
upgrade (C2) · KMS cloud account (E1) · vertical pick for the branded
compliance pack (E4) · human launch acts: HN post, grant submission, star
seeding (F1/F2/F4) · "merge" to land it all on main.
