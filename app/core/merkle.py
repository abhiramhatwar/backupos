"""
Merkle tree for backup snapshot integrity.

Leaves are the SHA-256 hashes of stored chunks.
Internal node hash = SHA-256(left.hash + right.hash).
Odd sibling is duplicated to form a complete binary tree.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MerkleNode:
    hash: str
    left: Optional["MerkleNode"] = field(default=None, repr=False)
    right: Optional["MerkleNode"] = field(default=None, repr=False)
    is_leaf: bool = False
    chunk_hash: Optional[str] = None  # only for leaves


class MerkleTree:
    def __init__(self, chunk_hashes: list[str]) -> None:
        self.chunk_hashes = list(chunk_hashes)
        self.root: Optional[MerkleNode] = self._build(self.chunk_hashes)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @staticmethod
    def _node_hash(left_hash: str, right_hash: str) -> str:
        combined = (left_hash + right_hash).encode()
        return hashlib.sha256(combined).hexdigest()

    def _build(self, hashes: list[str]) -> Optional[MerkleNode]:
        if not hashes:
            return None

        # Build leaf layer
        nodes: list[MerkleNode] = [
            MerkleNode(hash=h, is_leaf=True, chunk_hash=h) for h in hashes
        ]

        # Iteratively combine pairs until we reach the root
        while len(nodes) > 1:
            next_layer: list[MerkleNode] = []
            # Duplicate last node if the count is odd
            if len(nodes) % 2 == 1:
                nodes.append(nodes[-1])
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                right = nodes[i + 1]
                parent = MerkleNode(
                    hash=self._node_hash(left.hash, right.hash),
                    left=left,
                    right=right,
                )
                next_layer.append(parent)
            nodes = next_layer

        return nodes[0]

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def root_hash(self) -> str:
        if self.root is None:
            return hashlib.sha256(b"").hexdigest()
        return self.root.hash

    # ------------------------------------------------------------------
    # Diff
    # ------------------------------------------------------------------

    def diff(self, other: "MerkleTree") -> list[str]:
        """
        Return chunk hashes that are in *self* but absent from *other*.
        This identifies new or changed chunks compared to a previous snapshot.
        """
        other_set = set(other.chunk_hashes)
        return [h for h in self.chunk_hashes if h not in other_set]

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    @staticmethod
    def verify(chunk_hashes: list[str], expected_root: str) -> bool:
        """
        Rebuild a MerkleTree from *chunk_hashes* and compare its root to
        *expected_root*.  Returns True if they match.
        """
        tree = MerkleTree(chunk_hashes)
        return tree.root_hash == expected_root
