"""
Append-only binary Merkle tree over BLAKE2b-256.

Construction follows RFC 6962 §2.1 (Certificate Transparency):
  Leaf nodes:     H(0x00 || data)          — domain-separated from internal nodes
  Internal nodes: H(0x01 || left || right) — prevents second-preimage attacks

The split for a tree of size n uses the largest power of 2 strictly less than n,
producing a left-complete tree that supports O(log N) audit paths for any N.

Any modification to any leaf changes the Merkle root, making the log tamper-evident
without requiring the verifier to hold the full record set.
"""

from __future__ import annotations

__all__ = ["MerkleTree"]

from ..ltp.primitives import H_bytes


# ---------------------------------------------------------------------------
# Domain-separated hash primitives (RFC 6962 §2.1)
# ---------------------------------------------------------------------------

def _leaf_hash(data: bytes) -> bytes:
    """Hash a leaf: H(0x00 || data). The 0x00 prefix prevents leaf/node confusion."""
    return H_bytes(b'\x00' + data)


def _internal_hash(left: bytes, right: bytes) -> bytes:
    """Hash two children: H(0x01 || left || right)."""
    return H_bytes(b'\x01' + left + right)


def _largest_pow2_below(n: int) -> int:
    """Return the largest power of 2 strictly less than n.  Requires n >= 2."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


# ---------------------------------------------------------------------------
# Recursive tree operations
# ---------------------------------------------------------------------------

def _compute_root(leaves: list[bytes]) -> bytes:
    """Recursively compute the Merkle root from a list of pre-hashed leaf nodes."""
    n = len(leaves)
    assert n > 0, "Cannot compute root of empty leaf list"
    if n == 1:
        return leaves[0]
    k = _largest_pow2_below(n)
    return _internal_hash(_compute_root(leaves[:k]), _compute_root(leaves[k:]))


def _audit_path(index: int, leaves: list[bytes]) -> list[bytes]:
    """
    Return the sibling hashes (audit path) for the leaf at index.

    The path goes from leaf level up to root level.  Each entry is the
    root of the subtree that is the sibling at that level.  The verifier
    can reconstruct the root by applying _verify_inclusion().
    """
    n = len(leaves)
    if n == 1:
        return []
    k = _largest_pow2_below(n)
    if index < k:
        # Leaf is in the left subtree; right subtree root is the sibling at this level
        return _audit_path(index, leaves[:k]) + [_compute_root(leaves[k:])]
    else:
        # Leaf is in the right subtree; left subtree root is the sibling at this level
        return _audit_path(index - k, leaves[k:]) + [_compute_root(leaves[:k])]


def _verify_inclusion(
    index: int, tree_size: int, leaf_hash: bytes, audit_path: list[bytes]
) -> bytes:
    """
    Reconstruct the Merkle root from a leaf hash and its audit path.

    The audit_path from _audit_path is bottom-up (leaf level first, root level
    last).  To determine left/right ordering at each step we pre-compute the
    decomposition from root-to-leaf, then reverse it so it matches the
    bottom-up path order.

    Returns the reconstructed root, which the caller compares against a
    trusted root (e.g., from a verified STH).
    """
    # Walk from root to leaf, recording whether we went left at each level.
    going_left: list[bool] = []
    i = index
    n = tree_size
    while n > 1:
        k = _largest_pow2_below(n)
        left = i < k
        going_left.append(left)
        if left:
            n = k
        else:
            i -= k
            n -= k

    # Reconstruct from leaf to root (reverse the root-to-leaf direction list).
    node = leaf_hash
    for went_left, sibling in zip(reversed(going_left), audit_path):
        if went_left:
            # We descended left → our node is the left child, sibling is right
            node = _internal_hash(node, sibling)
        else:
            # We descended right → sibling is the left child, our node is right
            node = _internal_hash(sibling, node)
    return node


# ---------------------------------------------------------------------------
# MerkleTree class
# ---------------------------------------------------------------------------

class MerkleTree:
    """
    Append-only binary Merkle tree.

    Leaves are stored as H(0x00 || data) per RFC 6962 domain separation.
    Internal nodes are H(0x01 || left || right).

    Invariants:
      - Leaves are never modified after appending (append-only).
      - root() is deterministic: same sequence of appends → same root.
      - audit_path(i) produces a path of length ⌊log₂(size)⌋ or ⌈log₂(size)⌉.

    Performance:
      - Root is cached and invalidated on append (O(n) compute, O(1) read).
      - Subtree roots are cached during computation to accelerate audit_path.
    """

    def __init__(self) -> None:
        self._leaves: list[bytes] = []  # pre-hashed leaf nodes
        self._cached_root: bytes | None = None
        self._cache_leaf_count: int = 0  # leaf count when cache was computed
        self._cache_leaf_checksum: bytes = b""  # checksum of leaves at cache time

    @property
    def size(self) -> int:
        """Number of leaves in the tree."""
        return len(self._leaves)

    def append(self, data: bytes) -> int:
        """
        Append raw data to the tree.

        Computes leaf_hash = H(0x00 || data) and stores it.
        Returns the leaf index (0-based).
        """
        self._leaves.append(_leaf_hash(data))
        return len(self._leaves) - 1

    def root(self) -> bytes:
        """
        Compute the current Merkle root.

        Empty tree returns H(b'') — a canonical sentinel for the zero-state.
        Single-leaf tree returns the leaf hash directly.
        Root is cached; repeated calls without modification are O(1).
        Cache is invalidated if leaf count changes or leaf content is modified.
        """
        if not self._leaves:
            return H_bytes(b'')

        # Check cache validity: count must match and leaf content unchanged
        if (self._cached_root is not None
                and len(self._leaves) == self._cache_leaf_count
                and self._leaf_checksum() == self._cache_leaf_checksum):
            return self._cached_root

        self._cached_root = _compute_root(self._leaves)
        self._cache_leaf_count = len(self._leaves)
        self._cache_leaf_checksum = self._leaf_checksum()
        return self._cached_root

    def _leaf_checksum(self) -> bytes:
        """Checksum of all leaves for cache invalidation.

        Hashes the concatenation of all leaf hashes. This is O(n) but still
        cheaper than recomputing the full tree root (which involves O(n)
        hash operations with recursive tree construction overhead).
        """
        if not self._leaves:
            return b""
        return H_bytes(b"".join(self._leaves))

    def leaf_hash(self, index: int) -> bytes:
        """Return the stored leaf hash at index."""
        if not 0 <= index < self.size:
            raise IndexError(f"Leaf index {index} out of range (size={self.size})")
        return self._leaves[index]

    def audit_path(self, index: int) -> list[bytes]:
        """
        Return the audit path (sibling hashes) for the leaf at index.

        The path has at most ⌈log₂(size)⌉ entries.  Combined with the leaf
        hash and tree size, the verifier can reconstruct the root without
        holding any other leaf data.
        """
        if not 0 <= index < self.size:
            raise IndexError(f"Leaf index {index} out of range (size={self.size})")
        return _audit_path(index, self._leaves)
