"""
Shannon entropy analysis for ransomware / encryption detection.

A Shannon entropy of >7.5 bits/byte is a strong signal that data is
encrypted or compressed — a potential ransomware indicator.
"""
from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy in bits per byte (range 0.0 – 8.0).

    * 0.0 = all bytes identical (degenerate distribution, e.g. b'\\x00' * n)
    * 8.0 = all 256 byte values appear with equal frequency (maximum entropy)
    * >7.5 = highly compressed or encrypted data
    """
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def analyze_chunks(chunks: list[bytes]) -> dict:
    """
    Compute entropy statistics across a list of chunks.

    Returns a dict with keys:
      - average_entropy  (float)
      - max_entropy      (float)
      - high_entropy_ratio  (float) — fraction of chunks with entropy > 7.2
      - is_suspicious    (bool)
    """
    if not chunks:
        return {
            "average_entropy": 0.0,
            "max_entropy": 0.0,
            "high_entropy_ratio": 0.0,
            "is_suspicious": False,
        }

    HIGH_THRESHOLD = 7.2
    entropies = [shannon_entropy(c) for c in chunks]
    avg = sum(entropies) / len(entropies)
    maximum = max(entropies)
    high_count = sum(1 for e in entropies if e > HIGH_THRESHOLD)
    high_ratio = high_count / len(entropies)

    is_suspicious = avg > HIGH_THRESHOLD or high_ratio > 0.8

    return {
        "average_entropy": avg,
        "max_entropy": maximum,
        "high_entropy_ratio": high_ratio,
        "is_suspicious": is_suspicious,
    }


def entropy_spike_detected(
    current_avg: float,
    previous_avg: float,
    threshold: float = 7.2,
) -> bool:
    """
    Return True if *current_avg* is suspicious (above threshold) AND it has
    jumped significantly (by more than 1.5 bits/byte) from *previous_avg*.

    Returns False when previous_avg is 0.0 — no baseline has been established
    yet (first backup), so no comparison is possible.
    """
    if previous_avg == 0.0:
        return False
    return current_avg > threshold and (current_avg - previous_avg) > 1.5
