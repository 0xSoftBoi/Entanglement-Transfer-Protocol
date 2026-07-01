/*
 * etp-custody in-browser receipt verifier (no dependencies).
 *
 * Reproduces, byte-for-byte, the Python verification path:
 *   - SHA3-256 (canonical lane) for sealed/content hashes and the Merkle tree
 *   - CaptureManifest.canonical_bytes() (domain-tagged CanonicalEncoder subset)
 *   - RFC 6962 inclusion verification (merkle_log/tree.py port)
 *   - Keccak-256 for the eth_call selector of isAnchored(bytes32)
 *
 * What it deliberately does NOT do: ML-DSA-65 signature verification (the
 * operator STH and device signatures). Post-quantum signature verification in
 * hand-written browser JS is not a sound idea; the page delegates that check
 * to the notary's public /v1/verify endpoint (receipts are public data) and
 * labels it accordingly. The CLI remains the gold-standard offline verifier.
 *
 * Runs in both browser and Node (module.exports guard at the bottom) so the
 * test suite cross-checks it against the Python implementation.
 */
"use strict";

/* ---------------------------------------------------------------- Keccak */

const KECCAK_RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an,
  0x8000000080008000n, 0x000000000000808bn, 0x0000000080000001n,
  0x8000000080008081n, 0x8000000000008009n, 0x000000000000008an,
  0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n,
  0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n,
  0x000000000000800an, 0x800000008000000an, 0x8000000080008081n,
  0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
// Rotation offsets r[x][y]; rows are x = 0..4, so flat index is 5x + y.
const KECCAK_ROT = [
   0n, 36n,  3n, 41n, 18n,
   1n, 44n, 10n, 45n,  2n,
  62n,  6n, 43n, 15n, 61n,
  28n, 55n, 25n, 21n, 56n,
  27n, 20n, 39n,  8n, 14n,
];
const MASK64 = (1n << 64n) - 1n;

function rotl64(v, n) {
  n %= 64n;
  return ((v << n) | (v >> (64n - n))) & MASK64;
}

function keccakF(state) {
  for (let round = 0; round < 24; round++) {
    // theta
    const c = new Array(5), d = new Array(5);
    for (let x = 0; x < 5; x++) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    for (let x = 0; x < 5; x++) {
      d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1n);
      for (let y = 0; y < 5; y++) state[x + 5 * y] ^= d[x];
    }
    // rho + pi:  B[y, (2x+3y)%5] = rot(A[x, y], r[x][y])
    const b = new Array(25);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(state[x + 5 * y], KECCAK_ROT[5 * x + y]);
      }
    }
    // chi
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        state[x + 5 * y] =
          b[x + 5 * y] ^ ((~b[((x + 1) % 5) + 5 * y] & MASK64) & b[((x + 2) % 5) + 5 * y]);
      }
    }
    // iota
    state[0] ^= KECCAK_RC[round];
  }
}

/** Keccak sponge, 256-bit output (rate 136). domainByte: 0x06 = SHA3, 0x01 = Keccak. */
function keccak256Core(bytes, domainByte) {
  const rate = 136;
  const padded = new Uint8Array(Math.ceil((bytes.length + 1) / rate) * rate);
  padded.set(bytes);
  padded[bytes.length] = domainByte;
  padded[padded.length - 1] |= 0x80;

  const state = new Array(25).fill(0n);
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let j = 7; j >= 0; j--) {
        lane = (lane << 8n) | BigInt(padded[off + i * 8 + j]);  // little-endian lanes
      }
      state[i] ^= lane;
    }
    keccakF(state);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let lane = state[i];
    for (let j = 0; j < 8; j++) {
      out[i * 8 + j] = Number(lane & 0xffn);
      lane >>= 8n;
    }
  }
  return out;
}

const sha3_256 = (bytes) => keccak256Core(bytes, 0x06);   // canonical lane
const keccak256 = (bytes) => keccak256Core(bytes, 0x01);  // Ethereum selectors

/* ------------------------------------------------------------- encoding */

function b64d(s) {
  if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(s, "base64"));
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

function concatBytes(parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

const utf8 = (s) => new TextEncoder().encode(s);

function u32be(n) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

function f64be(x) {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setFloat64(0, x, false);
  return out;
}

const lpBytes = (b) => concatBytes([u32be(b.length), b]);
const lpString = (s) => lpBytes(utf8(s));

const MANIFEST_DOMAIN = "GSX-LTP:provenance-capture:v1\x00";

/** Port of CaptureManifest.canonical_bytes() — the exact log-leaf bytes. */
function canonicalManifestBytes(m) {
  const metaKeys = Object.keys(m.meta || {}).sort();
  const metaParts = [u32be(metaKeys.length)];
  for (const k of metaKeys) {
    metaParts.push(lpString(k), lpString(String(m.meta[k])));
  }
  return concatBytes([
    utf8(MANIFEST_DOMAIN),
    lpString(m.capture_id),
    lpString(m.originator_id),
    f64be(m.captured_at),
    b64d(m.content_hash),
    b64d(m.sealed_hash),
    lpBytes(b64d(m.originator_vk || "")),
    lpBytes(b64d(m.originator_sig || "")),
    ...metaParts,
  ]);
}

/* ------------------------------------------------------------- RFC 6962 */

const leafHash = (data) => sha3_256(concatBytes([new Uint8Array([0x00]), data]));
const nodeHash = (l, r) => sha3_256(concatBytes([new Uint8Array([0x01]), l, r]));

function largestPow2Below(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** Port of merkle_log/tree.py::_verify_inclusion — reconstructs the root. */
function verifyInclusion(index, treeSize, leaf, auditPath) {
  const goingLeft = [];
  let i = index, n = treeSize;
  while (n > 1) {
    const k = largestPow2Below(n);
    const left = i < k;
    goingLeft.push(left);
    if (left) { n = k; } else { i -= k; n -= k; }
  }
  let node = leaf;
  goingLeft.reverse();
  for (let s = 0; s < auditPath.length; s++) {
    node = goingLeft[s] ? nodeHash(node, auditPath[s]) : nodeHash(auditPath[s], node);
  }
  return node;
}

/* --------------------------------------------------------------- verify */

/**
 * Verify a receipt against sealed-blob bytes. Pure hash/structure checks —
 * everything except the ML-DSA signatures (see module docstring).
 * Returns per-check booleans plus overall `structuralOk`.
 */
function verifyReceipt(receipt, sealedBytes) {
  const m = receipt.manifest;
  const proof = receipt.inclusion_proof;
  const sth = receipt.signed_tree_head;

  const sealedHashOk = bytesEqual(sha3_256(sealedBytes), b64d(m.sealed_hash));
  const leaf = leafHash(canonicalManifestBytes(m));
  const reconstructed = verifyInclusion(
    proof.leaf_index, proof.tree_size, leaf, proof.audit_path.map(b64d));
  const proofOk = bytesEqual(reconstructed, b64d(proof.root));
  const rootMatchesSth = bytesEqual(b64d(proof.root), b64d(sth.root));

  return {
    sealedHashOk,
    proofOk,
    rootMatchesSth,
    deviceSigned: !!(m.originator_vk && m.originator_vk.length),
    structuralOk: sealedHashOk && proofOk && rootMatchesSth,
  };
}

/* --------------------------------------------------- on-chain (browser) */

/** eth_call isAnchored(bytes32) on LTPAnchorRegistry via any JSON-RPC URL. */
async function isAnchoredOnChain(rpcUrl, contractAddress, digestBytes) {
  const selector = hex(keccak256(utf8("isAnchored(bytes32)"))).slice(0, 8);
  const data = "0x" + selector + hex(digestBytes);
  const resp = await fetch(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0", id: 1, method: "eth_call",
      params: [{ to: contractAddress, data }, "latest"],
    }),
  });
  const body = await resp.json();
  if (body.error) throw new Error(body.error.message || "rpc error");
  return BigInt(body.result) === 1n;
}

/* ---------------------------------------------------------------- export */

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    sha3_256, keccak256, hex, b64d,
    canonicalManifestBytes, leafHash, nodeHash,
    verifyInclusion, verifyReceipt, isAnchoredOnChain,
  };
}
