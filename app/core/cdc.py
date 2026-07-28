"""
Content-Defined Chunking using Rabin fingerprinting.

Rolling hash window: 48 bytes
Target chunk size: ~2KB average (mask 0x1FFF)
Min chunk: 512 bytes, Max chunk: 8192 bytes
Polynomial: 0x3DA3358B4DC173
"""
from __future__ import annotations

from typing import Generator


class CDCChunker:
    WINDOW_SIZE = 48
    MIN_CHUNK = 512
    MAX_CHUNK = 8192
    TARGET_MASK = 0x1FFF  # ~2KB average
    POLY = 0x3DA3358B4DC173
    _U64 = 0xFFFFFFFFFFFFFFFF

    def __init__(self) -> None:
        self._build_tables()

    def _build_tables(self) -> None:
        """
        Precompute out_table[b] = b * POLY^WINDOW_SIZE mod 2^64.
        When a byte exits the sliding window it must be subtracted from
        the rolling hash weighted by POLY^WINDOW_SIZE.
        """
        poly_pow = 1
        for _ in range(self.WINDOW_SIZE):
            poly_pow = (poly_pow * self.POLY) & self._U64

        self.out_table = [(b * poly_pow) & self._U64 for b in range(256)]

    def _rolling_hash(self, data: bytes, start: int) -> tuple[int, list[int]]:
        """
        Seed the rolling hash over the first WINDOW_SIZE bytes starting at
        `start`.  Returns (hash_value, window_deque_as_list).
        The hash represents: sum(data[start+j] * POLY^j for j in 0..W-1).
        """
        h = 0
        window: list[int] = []
        end = min(start + self.WINDOW_SIZE, len(data))
        for i in range(start, end):
            b = data[i]
            h = (h * self.POLY + b) & self._U64
            window.append(b)
        # Pad if data shorter than window
        while len(window) < self.WINDOW_SIZE:
            window.append(0)
        return h, window

    def chunk_data(self, data: bytes) -> list[bytes]:
        """
        Split *data* into variable-length chunks using Rabin fingerprinting.
        Returns a list of byte strings that concatenate to the original data.
        """
        if not data:
            return []

        chunks: list[bytes] = []
        pos = 0
        n = len(data)

        while pos < n:
            # Seed the rolling hash for the current window
            h, window = self._rolling_hash(data, pos)
            win_pos = 0  # circular index into window
            chunk_start = pos
            # Advance past the minimum chunk size without checking boundary
            fast_forward = min(pos + self.MIN_CHUNK, n)
            pos = fast_forward

            # Now scan for a boundary
            while pos < n:
                out_byte = window[win_pos % self.WINDOW_SIZE]
                in_byte = data[pos]
                h = (h * self.POLY - self.out_table[out_byte] + in_byte) & self._U64
                window[win_pos % self.WINDOW_SIZE] = in_byte
                win_pos += 1
                pos += 1

                chunk_len = pos - chunk_start
                if chunk_len >= self.MAX_CHUNK:
                    break
                if (h & self.TARGET_MASK) == 0 and chunk_len >= self.MIN_CHUNK:
                    break

            chunks.append(data[chunk_start:pos])

        return chunks

    def chunk_file(self, path: str) -> Generator[bytes, None, None]:
        """
        Read a file in streaming fashion and yield chunks.
        Reads the entire file into memory and uses chunk_data for simplicity
        while keeping a generator interface for API compatibility.
        """
        with open(path, "rb") as f:
            data = f.read()
        for chunk in self.chunk_data(data):
            yield chunk
