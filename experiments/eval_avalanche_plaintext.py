# experiments/eval_avalanche_plaintext.py
import random
from experiments.common_eval import (
    random_u16, random_bit_index_16, flip_one_bit_16,
    popcount16, summarize_counts, to_percent
)

from src.saes_baseline import encrypt_saes
from src.saes_enhanced import encrypt_saes_enhanced

def run_plaintext_avalanche(trials=5000, seed=42):
    random.seed(seed)

    base_changes = []
    enh_changes = []

    for _ in range(trials):
        p = random_u16()
        k = random_u16()

        b = random_bit_index_16()
        p2 = flip_one_bit_16(p, b)

        c_base = encrypt_saes(p, k)
        c_base2 = encrypt_saes(p2, k)
        diff_base = popcount16(c_base ^ c_base2)
        base_changes.append(diff_base)

        c_enh = encrypt_saes_enhanced(p, k)
        c_enh2 = encrypt_saes_enhanced(p2, k)
        diff_enh = popcount16(c_enh ^ c_enh2)
        enh_changes.append(diff_enh)

    s_base = summarize_counts(base_changes)
    s_enh = summarize_counts(enh_changes)

    return s_base, s_enh, base_changes, enh_changes

if __name__ == "__main__":
    s_base, s_enh, _, _ = run_plaintext_avalanche(trials=5000)

    print("=== Plaintext Avalanche (flip 1 plaintext bit) ===")
    print(f"Trials: {s_base['n']}")
    print(f"Baseline avg changed bits: {s_base['avg']:.3f} / 16  ({to_percent(s_base['avg']):.2f}%)"
          f" | min={s_base['min']} max={s_base['max']} std={s_base['std']:.3f}")
    print(f"Enhanced avg changed bits: {s_enh['avg']:.3f} / 16  ({to_percent(s_enh['avg']):.2f}%)"
          f" | min={s_enh['min']} max={s_enh['max']} std={s_enh['std']:.3f}")
