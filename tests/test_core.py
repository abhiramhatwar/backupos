"""
Unit tests for core algorithm modules.

These tests are pure Python — no database, no HTTP client.
"""
import hashlib
import os
import tempfile

import pytest

from app.core.cas import CASStore
from app.core.cdc import CDCChunker
from app.core.entropy import (
    analyze_chunks,
    chi_squared_uniform_test,
    entropy_spike_detected,
    ewma_entropy_baseline,
    shannon_entropy,
)
from app.core.merkle import MerkleTree


# ===========================================================================
# CDC — Content-Defined Chunking
# ===========================================================================


class TestCDCChunker:
    def setup_method(self):
        self.chunker = CDCChunker()

    def test_chunks_reassemble_to_original(self):
        """Chunked data must concatenate back to the original bytes."""
        data = b"Hello World! " * 500  # 6500 bytes
        chunks = self.chunker.chunk_data(data)
        assert b"".join(chunks) == data

    def test_empty_data_returns_empty_list(self):
        assert self.chunker.chunk_data(b"") == []

    def test_small_data_returns_single_chunk(self):
        """Data smaller than MIN_CHUNK is returned as one chunk."""
        data = b"x" * 100
        chunks = self.chunker.chunk_data(data)
        assert len(chunks) == 1
        assert chunks[0] == data

    def test_chunk_sizes_within_bounds(self):
        """All chunks must respect MIN_CHUNK / MAX_CHUNK boundaries."""
        data = os.urandom(64 * 1024)  # 64 KB of random data
        chunks = self.chunker.chunk_data(data)
        for i, chunk in enumerate(chunks):
            assert len(chunk) >= CDCChunker.MIN_CHUNK or i == len(chunks) - 1, (
                f"Chunk {i} is too small: {len(chunk)} bytes"
            )
            assert len(chunk) <= CDCChunker.MAX_CHUNK, (
                f"Chunk {i} is too large: {len(chunk)} bytes"
            )

    def test_deterministic_chunking(self):
        """Same input must always produce the same chunk boundaries."""
        data = b"Deterministic test data " * 300
        chunks_a = self.chunker.chunk_data(data)
        chunks_b = self.chunker.chunk_data(data)
        assert chunks_a == chunks_b

    def test_chunk_file(self, tmp_path):
        """chunk_file must yield the same result as chunk_data."""
        fpath = tmp_path / "test.bin"
        data = b"File chunking test " * 400
        fpath.write_bytes(data)

        file_chunks = list(self.chunker.chunk_file(str(fpath)))
        data_chunks = self.chunker.chunk_data(data)
        assert file_chunks == data_chunks


# ===========================================================================
# CAS — Content-Addressable Storage
# ===========================================================================


class TestCASStore:
    def test_store_and_retrieve(self, tmp_path):
        cas = CASStore(str(tmp_path / "cas"))
        data = b"Hello, CAS!"
        digest, is_new, stored_bytes = cas.store(data)

        assert is_new is True
        assert isinstance(digest, str)
        assert len(digest) == 64  # SHA-256 hex
        assert stored_bytes > 0

        retrieved = cas.retrieve(digest)
        assert retrieved == data

    def test_dedup_second_store_is_not_new(self, tmp_path):
        cas = CASStore(str(tmp_path / "cas"))
        data = b"Duplicate chunk"
        _, is_new_first, _ = cas.store(data)
        digest, is_new_second, _ = cas.store(data)

        assert is_new_first is True
        assert is_new_second is False  # dedup

    def test_exists(self, tmp_path):
        cas = CASStore(str(tmp_path / "cas"))
        data = b"Exists test"
        digest, *_ = cas.store(data)
        assert cas.exists(digest) is True
        assert cas.exists("0" * 64) is False

    def test_retrieve_missing_raises(self, tmp_path):
        cas = CASStore(str(tmp_path / "cas"))
        with pytest.raises(FileNotFoundError):
            cas.retrieve("a" * 64)

    def test_delete(self, tmp_path):
        cas = CASStore(str(tmp_path / "cas"))
        data = b"delete me"
        digest, *_ = cas.store(data)
        assert cas.exists(digest) is True
        assert cas.delete(digest) is True
        assert cas.exists(digest) is False
        assert cas.delete(digest) is False  # idempotent

    def test_total_size(self, tmp_path):
        cas = CASStore(str(tmp_path / "cas"))
        data1 = b"chunk one" * 10
        data2 = b"chunk two" * 10
        cas.store(data1)
        cas.store(data2)
        size = cas.total_size()
        # With transparent compression the on-disk size may be smaller than raw
        assert 0 < size <= len(data1) + len(data2)

    def test_sha256_digest_correctness(self, tmp_path):
        cas = CASStore(str(tmp_path / "cas"))
        data = b"Known data"
        expected = hashlib.sha256(data).hexdigest()
        digest, *_ = cas.store(data)
        assert digest == expected

    def test_compression_is_transparent(self, tmp_path):
        """retrieve() must return original bytes regardless of on-disk encoding."""
        cas = CASStore(str(tmp_path / "cas"))
        # Low-entropy data → will be compressed
        data_low = b"\xAB\xCD" * 4096
        digest, *_ = cas.store(data_low)
        assert cas.retrieve(digest) == data_low

        # High-entropy data → stored raw
        data_high = os.urandom(4096)
        digest2, *_ = cas.store(data_high)
        assert cas.retrieve(digest2) == data_high


# ===========================================================================
# Merkle Tree
# ===========================================================================


class TestMerkleTree:
    def test_single_leaf(self):
        hashes = ["aabbcc" + "0" * 58]
        tree = MerkleTree(hashes)
        assert tree.root_hash == hashes[0]

    def test_two_leaves(self):
        hashes = ["a" * 64, "b" * 64]
        tree = MerkleTree(hashes)
        expected = hashlib.sha256(("a" * 64 + "b" * 64).encode()).hexdigest()
        assert tree.root_hash == expected

    def test_empty_tree(self):
        tree = MerkleTree([])
        assert tree.root is None
        expected_empty = hashlib.sha256(b"").hexdigest()
        assert tree.root_hash == expected_empty

    def test_root_hash_deterministic(self):
        hashes = [hashlib.sha256(f"chunk{i}".encode()).hexdigest() for i in range(8)]
        tree_a = MerkleTree(hashes)
        tree_b = MerkleTree(hashes)
        assert tree_a.root_hash == tree_b.root_hash

    def test_diff_returns_new_chunks(self):
        base = [hashlib.sha256(f"c{i}".encode()).hexdigest() for i in range(4)]
        extra = hashlib.sha256(b"new_chunk").hexdigest()
        new_tree = MerkleTree(base + [extra])
        old_tree = MerkleTree(base)
        diff = new_tree.diff(old_tree)
        assert extra in diff
        for h in base:
            assert h not in diff

    def test_diff_identical_trees(self):
        hashes = [hashlib.sha256(f"h{i}".encode()).hexdigest() for i in range(4)]
        tree = MerkleTree(hashes)
        assert tree.diff(tree) == []

    def test_verify_valid(self):
        hashes = [hashlib.sha256(f"v{i}".encode()).hexdigest() for i in range(5)]
        tree = MerkleTree(hashes)
        assert MerkleTree.verify(hashes, tree.root_hash) is True

    def test_verify_tampered(self):
        hashes = [hashlib.sha256(f"t{i}".encode()).hexdigest() for i in range(4)]
        tree = MerkleTree(hashes)
        tampered = list(hashes)
        tampered[0] = "0" * 64
        assert MerkleTree.verify(tampered, tree.root_hash) is False


# ===========================================================================
# Entropy
# ===========================================================================


class TestEntropy:
    def test_random_bytes_high_entropy(self):
        data = os.urandom(4096)
        e = shannon_entropy(data)
        assert e > 7.0, f"Expected entropy > 7.0 for random data, got {e}"

    def test_repeated_bytes_low_entropy(self):
        data = b"\x00" * 4096
        e = shannon_entropy(data)
        assert e < 1.0, f"Expected entropy < 1.0 for constant bytes, got {e}"

    def test_entropy_empty_data(self):
        assert shannon_entropy(b"") == 0.0

    def test_entropy_range(self):
        for _ in range(5):
            data = os.urandom(1024)
            e = shannon_entropy(data)
            assert 0.0 <= e <= 8.0

    def test_analyze_chunks_suspicious(self):
        chunks = [os.urandom(2048) for _ in range(10)]
        result = analyze_chunks(chunks)
        assert result["average_entropy"] > 7.0
        assert result["is_suspicious"] is True

    def test_analyze_chunks_not_suspicious(self):
        chunks = [b"\xAA" * 2048 for _ in range(10)]
        result = analyze_chunks(chunks)
        assert result["average_entropy"] < 2.0
        assert result["is_suspicious"] is False

    def test_analyze_empty_chunks(self):
        result = analyze_chunks([])
        assert result["average_entropy"] == 0.0
        assert result["is_suspicious"] is False

    def test_entropy_spike_detected_true(self):
        assert entropy_spike_detected(7.5, 4.0, threshold=7.2) is True

    def test_entropy_spike_detected_false_low_current(self):
        assert entropy_spike_detected(5.0, 4.0, threshold=7.2) is False

    def test_entropy_spike_detected_false_small_jump(self):
        # High current but no spike (small delta)
        assert entropy_spike_detected(7.5, 7.0, threshold=7.2) is False

    def test_entropy_spike_detected_false_zero_baseline(self):
        # First backup has no baseline → must not fire a false alert
        assert entropy_spike_detected(7.9, 0.0, threshold=7.2) is False

    def test_chi_squared_encrypted_data(self):
        data = os.urandom(4096)
        p = chi_squared_uniform_test(data)
        # Random bytes → near-uniform → high p-value
        assert p > 0.01, f"Expected high p-value for random data, got {p}"

    def test_chi_squared_repetitive_data(self):
        data = (b"hello world " * 200)[:4096]
        p = chi_squared_uniform_test(data)
        # Non-uniform ASCII text → very low p-value
        assert p < 0.01, f"Expected low p-value for repetitive text, got {p}"

    def test_chi_squared_small_data_returns_inconclusive(self):
        p = chi_squared_uniform_test(b"tiny")
        assert p == 0.5

    def test_ewma_entropy_baseline_empty(self):
        assert ewma_entropy_baseline([]) == 0.0

    def test_ewma_entropy_baseline_single(self):
        assert ewma_entropy_baseline([5.0]) == 5.0

    def test_ewma_entropy_baseline_weighted(self):
        # With alpha=1.0 the result collapses to the last value
        result = ewma_entropy_baseline([1.0, 2.0, 3.0], alpha=1.0)
        assert result == 3.0

    def test_ewma_entropy_baseline_smoothing(self):
        # Baseline should be closer to older values when alpha is low
        result_low = ewma_entropy_baseline([7.0, 3.0], alpha=0.1)
        result_high = ewma_entropy_baseline([7.0, 3.0], alpha=0.9)
        # Low alpha → more weight on history (7.0), so higher result
        assert result_low > result_high
