# experiments/common_eval.py
import random

def popcount16(x: int) -> int:
    x &= 0xFFFF
    # Python 3.8+: int.bit_count()
    return x.bit_count()

def flip_one_bit_16(x: int, bit_index: int) -> int:
    return (x ^ (1 << bit_index)) & 0xFFFF

def random_u16() -> int:
    return random.getrandbits(16)

def random_bit_index_16() -> int:
    return random.randrange(16)

def summarize_counts(counts):
    # counts: list of integers (0..16)
    n = len(counts)
    avg = sum(counts) / n
    mn = min(counts)
    mx = max(counts)
    # simple variance/std
    var = sum((c - avg) ** 2 for c in counts) / n
    std = var ** 0.5
    return {"n": n, "avg": avg, "min": mn, "max": mx, "std": std}

def to_percent(x, total=16):
    return (x / total) * 100.0
