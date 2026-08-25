# Execution Plan — Finishing ETP Custody Cloud

What remains between the current state (working multi-tenant service + anchor
lifecycle + full design, branch `claude/satellite-cubesat-scope-7w6o7t`) and a
launched, revenue-capable product. Phases are dependency-ordered; within a
phase, items are independent. Effort: **S** < half a day, **M** 1–3 days,
**L** ~1 week. Owner: **[auto]** = buildable in-session with no external
dependency; **[you]** = needs your account, secret, or human action.

---

## Phase A — Ship & smoke-test what exists (now)

| # | Item | Effort | Owner | Notes |
|---|---|---|---|---|
| A1 | Open + merge the cloud-layer PR | S | [auto]→[you] | Same flow as PR #4; say "merge" |
| A2 | Deploy `website/` (Vercel connector is available) | S | [you] approve → [auto] | Outward-facing — needs your go-ahead; custom domain optional |
| A3 | ✅ Terminal demo cast (`website/demo.cast`, asciinema v2, from a real run) linked in README | S | done | The launch playbook's highest-converting README element |
| A4 | **Real-chain smoke test**: run `AnchorWorker.run_once()` against GSX Testnet via the real `AnchorClient` | S | **[you]** | Blocked on secrets: `GSX_RPC_URL` + a funded anchoring key (`contracts/.env` is gitignored, not in this container). Everything else is already wired |
| A5 | CI green on GitHub (the new `ci.yml` runs on next push/PR) | S | [auto] | Watch first run; fix any env drift |

**Exit criteria:** merged main, live site, a real `Anchored` event on GSX for a
custody STH, CI badge truthful.

## Phase B — Production-grade service (design M1)

| # | Item | Effort | Owner | Notes |
|---|---|---|---|---|
| B1 | ✅ **Event indexer** (`cloud/indexer.py`): `Anchored` logs behind a narrow LogSource interface, confirmation-depth finality, persisted cursor, crashed-worker recovery; `reconcile()` kept as safety net | M | done | Real-chain test still needs A4's RPC |
| B2 | ✅ **Webhook outbox** (`cloud/webhooks.py`): persistent rows, exponential backoff, `X-ETP-Signature` sha3-256 HMAC per-tenant secret | M | done | |
| B3 | ✅ **Idempotent `POST /v1/captures`** (dedupe on `capture_id`, 200 vs 201, replay-safe across restarts, not double-metered) + per-key token-bucket rate limits (429 + Retry-After; reuses anchor client's `TokenBucketRateLimiter`) | S | done | |
| B4 | ✅ **Postgres + FastAPI port**: `PostgresStore` (dialect layer, same schema/behavior, tested in CI via a postgres service container), `cloud/api.py` FastAPI app with the identical contract (401/400/404/429/201-vs-200, same error envelope — SDK works unchanged), `cloud/worker.py` entrypoint, `docker-compose.yml` (postgres+api+worker), deps isolated in the `[cloud]` extra | L | done | SQLite/stdlib server remains the reference |
| B5 | ✅ Observability: `GET /metrics` Prometheus text exposition (`cloud/metrics.py`, hand-rolled, both HTTP layers) — tenants, captures (total + per-tenant), anchors by status, outbox backlog | M | done | Alert *rules* (anchor-stuck, signer balance) live in the scrape config, not the app; design §12 |

**Exit criteria:** service survives kill -9 mid-anchor with zero duplicate
txs (already unit-proven; re-proven on Postgres), webhooks retry, p95 measured.

## Phase C — Console MVP (design M1/M2)

Order matters: the public verifier first (no auth, highest trust leverage),
then the authenticated console.

| # | Item | Effort | Owner | Notes |
|---|---|---|---|---|
| C1 | ✅ **`/verify` public page** (`website/verify.html` + `verify.js`): paste receipt/attestation + drop sealed file → hashing + RFC-6962 inclusion **in-browser** (hand-written SHA3/Keccak, cross-tested vs Python under node); ML-DSA checks delegated to the public `POST /v1/verify` endpoint, honestly labeled; `isAnchored` via raw `eth_call` (read-only, **no wallet, no viem dep**) | M | done | Full offline PQ verification remains the CLI's job — stated on the page |
| C2 | ✅ *(v1, static)* Console shipped as `website/console.html` — API-key auth (localStorage), zero build step. The Next.js + OAuth shell remains a post-creds upgrade | M | done ([you] OAuth creds for v2) | Scope decision in `ONE_SHOT_PLAN.md` |
| C3 | ✅ *(v1)* Dashboard tiles (usage, latest STH, anchors confirmed), captures table w/ attestation status, anchors table w/ status chips | M–L | done | Consumes existing API only; key mgmt + tx→explorer links in v2 |
| C4 | Deploy console (Vercel) + point `api.` at the service | S | [you] approve | |

**Exit criteria:** a stranger can verify a receipt in the browser and see an
ANCHORED badge; a customer can self-serve keys and watch anchors confirm.

## Phase D — Monetization plumbing (design M2)

| # | Item | Effort | Owner | Notes |
|---|---|---|---|---|
| D1 | ✅ *(export half)* `cloud/billing.py`: idempotent usage snapshots + Stripe-metered-shaped JSONL export. Live API push still needs the Stripe connector | M | done; **[you]** for live push | Free = unanchored; Verified = anchored tier |
| D2 | ✅ Plan enforcement in worker (`anchor_plans`, default `verified`-only; `ETP_CLOUD_ANCHOR_PLANS`) + admin plan endpoint | S | done | |
| D3 | SSO/SAML + RBAC (the enterprise gate — per playbook, never gate crypto/verify) | L | later | Post-first-customer |

## Phase E — Trust upgrades (design M3, pre-enterprise)

| # | Item | Effort | Owner |
|---|---|---|---|
| E1 | ✅ *(operator half)* `cloud/keys.py`: Signer seam + AWS-KMS ML-DSA-65 impl (`ETP_CLOUD_KMS_KEY_ID`; key non-exportable, per-signature fail-fast verify; log/witness/service all signer-agnostic). Anchoring EOA via KMS lands with the funded-account smoke (A4) | M | done; [you] cloud account + KMS key to activate |
| E2 | ✅ `batchAnchor` aggregation (worker batches >1 pending into one tx when the client supports it) | S | done |
| E3 | ✅ Witness cosigning (`cloud/witness.py`: independent keypair countersigns STHs; cosignature in `/v1/sth`) | M | done |
| E4 | ✅ *(vertical-agnostic v1)* `cloud/report.py`: audit evidence bundle (JSON+MD), claims verified at generation time. 21-CFR-11/NERC-CIP framing waits on the design partner | L | done; [you] pick vertical for the branded pack |

## Phase F — Launch (parallel with B/C; from `docs/FREE_OPEN_PLAYBOOK.md`)

| # | Item | Effort | Owner | Notes |
|---|---|---|---|---|
| F1 | ✅ draft — `docs/launch/show-hn.md` (title, first comment, Q&A prep) | S | drafted; **[you]** post | Monday ~8–9am ET; be in comments |
| F2 | ✅ draft — `docs/launch/nlnet-application.md` (form-shaped, €38k budget) | M | drafted; [you] submit | |
| F3 | ✅ drafts — `docs/launch/awesome-submissions.md` (4 list entries, repo topics, Homebrew formula) | S | drafted; [you] submit (outside repo scope) | |
| F4 | Seed first ~100 stars from your network **before** F1 | — | **[you]** | Playbook: a 3-star repo converts terribly on HN |
| F5 | ✅ draft — `docs/launch/sbir-onepager.md` (AFWERX-shaped, CNSA 2.0 gap stated) | M | drafted | The funded-buyer path |

---

## Critical path & sequencing

```
A1 merge ─▶ A5 CI ─▶ B1–B3 (indexer/outbox/idempotency) ─▶ B4 Postgres/FastAPI ─▶ C2–C4 console
        └▶ A2 site ─▶ C1 /verify ──────────────────────────────────────────┘
A4 chain smoke (needs your secrets — unblocks B1's real test, the ANCHORED badge, and launch credibility)
F runs parallel once A2 is live; D1 needs Stripe auth; D2/E2 are quick wins any time.
```

**Blocked-on-you summary (everything else is autonomous):**
1. "Merge" for the cloud PR (A1)
2. Go-ahead to deploy the site via Vercel (A2/C4)
3. `GSX_RPC_URL` + funded anchoring key for the real-chain smoke test (A4)
4. Stripe connector auth (D1) — currently unauthenticated in this session
5. OAuth app credentials for console sign-in (C2)
6. Human launch actions: HN post, grant submission, network seeding (F1/F2/F4)

**Recommended immediate order:** A1 → A3 → B1+B2+B3 (one batch) → C1 → B4 →
C2–C4, with A2/A4 whenever you provide the go-ahead/secrets, and F drafts
prepared in parallel so launch waits on nothing but you.
