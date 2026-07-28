"""
Content-Addressable Storage.

Chunks are stored by their SHA-256 hex digest under a two-level directory
structure:  <store_root>/<first-2-chars>/<remaining-chars>
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path


class CASStore:
    def __init__(self, store_path: str) -> None:
        self.root = Path(store_path)
        self.root.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _chunk_path(self, chunk_hash: str) -> Path:
        """Two-level shard: <root>/ab/cdef…"""
        return self.root / chunk_hash[:2] / chunk_hash[2:]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def store(self, data: bytes) -> tuple[str, bool]:
        """
        Persist *data* and return ``(sha256_hex, is_new)``.

        ``is_new`` is ``False`` when the chunk already existed (dedup hit).
        The write is atomic: data is written to a temp file then renamed.
        """
        digest = hashlib.sha256(data).hexdigest()
        path = self._chunk_path(digest)

        if path.exists():
            return digest, False

        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(".tmp")
        try:
            tmp_path.write_bytes(data)
            tmp_path.rename(path)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise

        return digest, True

    def retrieve(self, chunk_hash: str) -> bytes:
        """Return the stored bytes for *chunk_hash* or raise FileNotFoundError."""
        path = self._chunk_path(chunk_hash)
        if not path.exists():
            raise FileNotFoundError(f"Chunk not found in CAS: {chunk_hash}")
        return path.read_bytes()

    def exists(self, chunk_hash: str) -> bool:
        """Return True if the chunk is already stored."""
        return self._chunk_path(chunk_hash).exists()

    def total_size(self) -> int:
        """Return the sum of all stored chunk sizes in bytes."""
        total = 0
        for dirpath, _dirnames, filenames in os.walk(self.root):
            for fname in filenames:
                if not fname.endswith(".tmp"):
                    total += os.path.getsize(os.path.join(dirpath, fname))
        return total
