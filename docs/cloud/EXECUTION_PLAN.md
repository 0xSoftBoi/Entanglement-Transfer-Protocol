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
| A3 | Terminal demo cast (asciinema/VHS) for README + site | S | [auto] | The launch playbook's highest-converting README element |
| A4 | **Real-chain smoke test**: run `AnchorWorker.run_once()` against GSX Testnet via the real `AnchorClient` | S | **[you]** | Blocked on secrets: `GSX_RPC_URL` + a funded anchoring key (`contracts/.env` is gitignored, not in this container). Everything else is already wired |
| A5 | CI green on GitHub (the new `ci.yml` runs on next push/PR) | S | [auto] | Watch first run; fix any env drift |

**Exit criteria:** merged main, live site, a real `Anchored` event on GSX for a
custody STH, CI badge truthful.

## Phase B — Production-grade service (design M1)

| # | Item | Effort | Owner | Notes |
|---|---|---|---|---|
| B1 | **Event indexer**: consume `Anchored` logs w/ confirmation depth + `indexer_cursor`, reorg → revert row to `submitted`; keep `reconcile()` as safety net | M | [auto] | Testable now against a log-emitting fake; real test needs A4's RPC |
| B2 | **Webhook outbox**: persistent rows, exponential backoff, `X-ETP-Signature` HMAC; replaces best-effort threads | M | [auto] | Schema already in design §4 |
| B3 | **Idempotent `POST /v1/captures`** (dedupe on `capture_id`) + per-key rate limits | S | [auto] | Closes the double-submit gap |
| B4 | **Postgres + FastAPI port** behind the same OpenAPI; docker-compose (api + worker + postgres); keep stdlib/SQLite as the reference | L | [auto] | Adds the repo's first service deps — isolated in an optional extra `[cloud]` |
| B5 | Observability: structured logs, `/metrics` (Prometheus), anchor-stuck + signer-balance alerts | M | [auto] | Design §12 |

**Exit criteria:** service survives kill -9 mid-anchor with zero duplicate
txs (already unit-proven; re-proven on Postgres), webhooks retry, p95 measured.

## Phase C — Console MVP (design M1/M2)

Order matters: the public verifier first (no auth, highest trust leverage),
then the authenticated console.

| # | Item | Effort | Owner | Notes |
|---|---|---|---|---|
| C1 | **`/verify` public page**: paste receipt/attestation + drop sealed file → PASS/FAIL in-browser; `isAnchored` via viem (read-only, **no wallet**) | M | [auto] | Needs a JS verifier for SHA3-256 Merkle path + ML-DSA verify — port the verify path or compile to WASM; the one real technical risk in this phase |
| C2 | Console shell: Next.js 14 + Auth.js (GitHub/Google OAuth), `users`/`memberships` tables | M | [auto] build; [you] OAuth app creds | |
| C3 | Pages: dashboard, captures (+detail), keys, anchors timeline (tx → explorer) | M–L | [auto] | Consumes existing API only |
| C4 | Deploy console (Vercel) + point `api.` at the service | S | [you] approve | |

**Exit criteria:** a stranger can verify a receipt in the browser and see an
ANCHORED badge; a customer can self-serve keys and watch anchors confirm.

## Phase D — Monetization plumbing (design M2)

| # | Item | Effort | Owner | Notes |
|---|---|---|---|---|
| D1 | Stripe metered billing on `usage()` (nightly export, plan gating on `tenants.plan`) | M | **[you]**: authorize the Stripe connector → [auto] | Free = unanchored; Verified = anchored tier |
| D2 | Plan enforcement in worker (anchor only `plan='verified'` tenants) | S | [auto] | One query change |
| D3 | SSO/SAML + RBAC (the enterprise gate — per playbook, never gate crypto/verify) | L | later | Post-first-customer |

## Phase E — Trust upgrades (design M3, pre-enterprise)

| # | Item | Effort | Owner |
|---|---|---|---|
| E1 | KMS/HSM for operator + anchoring keys (kill the reference DB-stored key) | M | [auto] design + AWS-KMS impl; [you] cloud account |
| E2 | `batchAnchor` aggregation (many tenants per tx) | S | [auto] |
| E3 | Witness cosigning (second operator cross-signs STHs) | M | [auto] |
| E4 | Compliance report pack #1 (pick per first design partner: 21 CFR 11 or NERC-CIP) | L | [you] pick vertical → [auto] |

## Phase F — Launch (parallel with B/C; from `docs/FREE_OPEN_PLAYBOOK.md`)

| # | Item | Effort | Owner | Notes |
|---|---|---|---|---|
| F1 | Show HN draft + README polish (comparison table, cast at top) | S | [auto] draft; **[you]** post | Monday ~8–9am ET; be in comments |
| F2 | NLnet / NGI Zero application (€5–50k, funds the free core) | M | [auto] draft; [you] submit | |
| F3 | awesome-cryptography / awesome-security PRs, GitHub Topics, Homebrew tap | S | [auto] drafts; [you] submit (outside repo scope) | |
| F4 | Seed first ~100 stars from your network **before** F1 | — | **[you]** | Playbook: a 3-star repo converts terribly on HN |
| F5 | SBIR/DIU angle one-pager (evidence integrity / PQC migration) | M | [auto] draft | The funded-buyer path |

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
