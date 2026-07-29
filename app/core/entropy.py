"""
Shannon entropy analysis for ransomware / encryption detection.

A Shannon entropy of >7.5 bits/byte is a strong signal that data is
encrypted or compressed — a potential ransomware indicator.

chi_squared_uniform_test() distinguishes *encrypted* data (uniform byte
distribution, high p-value) from *compressed* data (non-uniform, low p-value).
Both have high Shannon entropy, so entropy alone produces false positives.

ewma_entropy_baseline() builds a stable historical baseline using exponential
smoothing so that a single legitimately-high-entropy snapshot doesn't break
the anomaly detector.
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


def chi_squared_uniform_test(data: bytes) -> float:
    """
    Goodness-of-fit test against a uniform distribution over all 256 byte values.

    Returns a p-value:
      * High p-value (>0.05): byte distribution looks uniform → likely *encrypted*
        (ransomware encrypts data, producing near-perfectly-uniform byte histograms)
      * Low p-value (<0.05): distribution is non-uniform → likely *compressed*
        (compressors are not truly random; entropy is high but not maximally uniform)

    Uses the Wilson–Hilferty normal approximation to the chi-squared CDF so that
    the scipy dependency is avoided.  Requires at least 512 bytes; returns 0.5
    (inconclusive) for smaller inputs.
    """
    if len(data) < 512:
        return 0.5

    counts = Counter(data)
    n = len(data)
    expected = n / 256.0

    chi2 = sum((counts.get(b, 0) - expected) ** 2 / expected for b in range(256))

    # Wilson–Hilferty approximation: (chi2/df)^(1/3) ≈ N(mu, sigma^2)
    df = 255
    mu = 1.0 - 2.0 / (9.0 * df)
    sigma = math.sqrt(2.0 / (9.0 * df))
    z = ((chi2 / df) ** (1.0 / 3.0) - mu) / sigma

    # Upper-tail p-value: P(chi2_255 > chi2_observed)
    return 0.5 * math.erfc(z / math.sqrt(2.0))


def ewma_entropy_baseline(recent_entropies: list[float], alpha: float = 0.3) -> float:
    """
    Compute an Exponentially Weighted Moving Average of historical entropy values.

    *recent_entropies* should be ordered oldest-first.  Alpha controls the
    smoothing: higher values weight recent observations more heavily.

    Returns 0.0 when the list is empty (no baseline established yet).
    """
    if not recent_entropies:
        return 0.0
    ewma = recent_entropies[0]
    for val in recent_entropies[1:]:
        ewma = alpha * val + (1.0 - alpha) * ewma
    return ewma
