"""
Content-Addressable Storage.

Chunks are stored by their SHA-256 hex digest under a two-level directory
structure:  <store_root>/<first-2-chars>/<remaining-chars>

Chunks with Shannon entropy < 7.2 bits/byte are transparently compressed with
zstandard (level 3) before writing.  retrieve() auto-detects the zstd magic
header and decompresses on read, so callers are always handed raw bytes.

store() returns (sha256_hex, is_new, stored_bytes):
  * sha256_hex   — digest of the *original* (uncompressed) data
  * is_new       — False when a chunk with that digest already existed (dedup hit)
  * stored_bytes — bytes actually written to disk (compressed or raw)
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

try:
    import zstandard as zstd

    _HAVE_ZSTD = True
except ImportError:
    _HAVE_ZSTD = False

_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_COMPRESS_ENTROPY_THRESHOLD = 7.2


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

    def store(self, data: bytes, entropy: float | None = None) -> tuple[str, bool, int]:
        """
        Persist *data* and return ``(sha256_hex, is_new, stored_bytes)``.

        The digest is always computed over the original *data* so callers can
        verify integrity independently of the on-disk encoding.

        ``is_new`` is ``False`` when the chunk already existed (dedup hit).
        ``stored_bytes`` is the number of bytes written to disk; it may be
        smaller than ``len(data)`` when compression is applied.

        Chunks with entropy below the threshold are zstd-compressed (level 3)
        before storage.  High-entropy chunks (encrypted / already compressed)
        are stored raw to avoid expansion.

        The write is atomic: data goes to a temp file then is renamed.
        """
        digest = hashlib.sha256(data).hexdigest()
        path = self._chunk_path(digest)

        if path.exists():
            return digest, False, path.stat().st_size

        path.parent.mkdir(parents=True, exist_ok=True)

        # Determine whether to compress
        if entropy is None:
            from app.core.entropy import shannon_entropy

            entropy = shannon_entropy(data)

        if _HAVE_ZSTD and entropy < _COMPRESS_ENTROPY_THRESHOLD:
            cctx = zstd.ZstdCompressor(level=3)
            payload = cctx.compress(data)
        else:
            payload = data

        tmp_path = path.with_suffix(".tmp")
        try:
            tmp_path.write_bytes(payload)
            tmp_path.rename(path)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise

        return digest, True, len(payload)

    def retrieve(self, chunk_hash: str) -> bytes:
        """Return the raw (decompressed) bytes for *chunk_hash*."""
        path = self._chunk_path(chunk_hash)
        if not path.exists():
            raise FileNotFoundError(f"Chunk not found in CAS: {chunk_hash}")
        data = path.read_bytes()
        if data[:4] == _ZSTD_MAGIC:
            if not _HAVE_ZSTD:
                raise RuntimeError(
                    "zstandard library is required to decompress this chunk but is not installed"
                )
            dctx = zstd.ZstdDecompressor()
            return dctx.decompress(data)
        return data

    def exists(self, chunk_hash: str) -> bool:
        """Return True if the chunk is already stored."""
        return self._chunk_path(chunk_hash).exists()

    def delete(self, chunk_hash: str) -> bool:
        """
        Remove a chunk from the store.

        Returns True if the chunk was found and deleted, False if it was not
        present.  Also removes the parent shard directory when it becomes empty.
        """
        path = self._chunk_path(chunk_hash)
        if not path.exists():
            return False
        path.unlink()
        try:
            path.parent.rmdir()
        except OSError:
            pass
        return True

    def total_size(self) -> int:
        """Return the sum of all on-disk chunk sizes in bytes (after compression)."""
        total = 0
        for dirpath, _dirnames, filenames in os.walk(self.root):
            for fname in filenames:
                if not fname.endswith(".tmp"):
                    total += os.path.getsize(os.path.join(dirpath, fname))
        return total

    def stats(self) -> dict:
        """Return storage statistics: chunk count and compressed bytes on disk."""
        chunk_count = 0
        compressed_bytes = 0
        for dirpath, _dirnames, filenames in os.walk(self.root):
            for fname in filenames:
                if fname.endswith(".tmp"):
                    continue
                chunk_count += 1
                compressed_bytes += os.path.getsize(os.path.join(dirpath, fname))
        return {"chunk_count": chunk_count, "compressed_bytes": compressed_bytes}
