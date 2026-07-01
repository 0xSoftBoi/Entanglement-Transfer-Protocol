#!/usr/bin/env sh
# etp-custody installer.
#   curl -fsSL https://raw.githubusercontent.com/0xSoftBoi/Entanglement-Transfer-Protocol/main/install.sh | sh
#
# Installs the `etp-custody` CLI with real post-quantum crypto (pqcrypto + pynacl)
# via pipx (isolated, preferred) or pip --user. Requires Python 3.10+.
set -eu

REPO="git+https://github.com/0xSoftBoi/Entanglement-Transfer-Protocol.git"
SPEC="ltp[crypto] @ ${REPO}"

echo "→ installing etp-custody (post-quantum chain-of-custody CLI)…"

if command -v pipx >/dev/null 2>&1; then
  pipx install "${SPEC}"
elif command -v python3 >/dev/null 2>&1; then
  echo "  (pipx not found; using pip --user — 'pipx' is recommended)"
  python3 -m pip install --user "${SPEC}"
else
  echo "error: need python3 (3.10+) on PATH." >&2
  exit 1
fi

echo
if command -v etp-custody >/dev/null 2>&1; then
  echo "✓ installed. Try:"
  echo "    etp-custody notarize yourfile.pdf --attest"
  echo "    etp-custody verify   yourfile.pdf"
else
  echo "✓ installed, but 'etp-custody' isn't on PATH yet."
  echo "  Add your user bin dir to PATH (pipx: 'pipx ensurepath'; pip --user: ~/.local/bin)."
fi
