#!/usr/bin/env bash
#
# custody_demo.sh — the whole etp-custody story, end to end, in one run.
#
# Walks the full lifecycle against a throwaway working directory:
#   keygen → init → send (device-signed, erasure-bundled) → simulate a lossy
#   link → inspect → receive (fail-closed, pinned) → audit (append-only) → batch.
#
# Usage:  bash examples/custody_demo.sh
# Requires real post-quantum crypto:  pip install -e ".[crypto]"
set -euo pipefail

# Resolve the repo root from this script's location, and pick a CLI invocation
# that works whether or not the package is installed.
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if command -v etp-custody >/dev/null 2>&1; then
  CLI() { etp-custody "$@"; }
else
  CLI() { PYTHONPATH="$REPO" python -m src.ltp.provenance_cli "$@"; }
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

say() { printf '\n\033[1;36m▸ %s\033[0m\n' "$*"; }

say "1. Generate keys — a notary operator, a recipient (Bob), a capturing device"
CLI keygen -o operator.key --label notary
CLI keygen -o bob.key      --label bob     --pub bob.pub
CLI keygen -o sensor7.key  --label sensor7 --pub sensor7.pub

say "2. Stand up the notary (append-only Merkle log)"
CLI init ./notary --operator operator.key

say "3. Create a confidential artifact"
echo "TOP SECRET — quarterly telemetry, confidential through 2045" > report.txt
cat report.txt | sed 's/^/    /'

say "4. send: seal (PQC) + notarize + device-sign + erasure-bundle (6 shards, any 4)"
CLI send ./notary --in report.txt --to bob.pub \
    --originator sensor-7 --originator-key sensor7.key \
    --n 6 --k 4 --prefix parcel

say "5. Simulate a lossy link: two shards never arrive"
rm parcel.shard001 parcel.shard004
echo "    dropped parcel.shard001 and parcel.shard004 (2 of 6)"

say "6. inspect the parcel with NO keys — structural triage before committing"
CLI inspect --receipt parcel.receipt --bundle parcel.bundle \
    parcel.shard000 parcel.shard002 parcel.shard003 parcel.shard005

say "7. receive: reassemble from survivors + verify (operator & device PINNED) + open"
CLI receive --key bob.key --bundle parcel.bundle --receipt parcel.receipt \
    --out recovered.txt --operator operator.key --expect-originator sensor7.pub \
    parcel.shard000 parcel.shard002 parcel.shard003 parcel.shard005
if diff -q report.txt recovered.txt >/dev/null; then
  echo "    ✓ recovered plaintext is byte-identical to the original"
fi

say "8. fail-closed: pin the WRONG device — provenance fails, nothing is opened"
if CLI receive --key bob.key --bundle parcel.bundle --receipt parcel.receipt \
    --out leak.txt --expect-originator bob.pub \
    parcel.shard000 parcel.shard002 parcel.shard003 parcel.shard005 2>/dev/null; then
  echo "    !! unexpected success"
else
  echo "    ✓ refused to open; no plaintext written: $([ -f leak.txt ] && echo LEAK || echo none)"
fi

say "9. batch-send a whole directory under ONE append-only log"
mkdir day
for i in 1 2 3; do echo "record $i" > "day/record_$i.dat"; done
CLI batch-send ./notary --in-dir day --to bob.pub --originator sensor-7 \
    --n 5 --k 3 --out-dir parcels

say "10. audit: prove two receipts belong to one append-only log (no rewrite/fork)"
CLI audit ./notary parcel.receipt parcels/record_1.dat.receipt

printf '\n\033[1;32m✓ done — post-quantum, tamper-evident, delay-tolerant custody, no blockchain.\033[0m\n'
