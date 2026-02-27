# src/saes_enhanced.py
from typing import List, Tuple
from src.saes_baseline import (
    SBOX, SBOX_INV,
    key_expand, state_from_u16, u16_from_state, xor_state,
    shift_rows, inv_shift_rows,
    mix_columns, inv_mix_columns,
    round_key_state
)

# ---------- Dynamic S-Box (per-round mask) ----------
def mask_from_round_key(k16: int) -> int:
    """
    Derive a 4-bit mask from the 16-bit round key.
    mask = XOR of the 4 nibbles of the round key.
    """
    n0 = (k16 >> 12) & 0xF
    n1 = (k16 >> 8) & 0xF
    n2 = (k16 >> 4) & 0xF
    n3 = k16 & 0xF
    return (n0 ^ n1 ^ n2 ^ n3) & 0xF

def sub_nib_dynamic(s: List[List[int]], kmask: int) -> List[List[int]]:
    """
    Dynamic SubNib using:
    S_k(x) = S(x XOR kmask) XOR kmask
    """
    out = [[0, 0], [0, 0]]
    for r in range(2):
        for c in range(2):
            x = s[r][c] & 0xF
            out[r][c] = (SBOX[x ^ kmask] ^ kmask) & 0xF
    return out

def inv_sub_nib_dynamic(s: List[List[int]], kmask: int) -> List[List[int]]:
    """
    Inverse for the dynamic S-Box:
    S_k^{-1}(y) = S^{-1}(y XOR kmask) XOR kmask
    """
    out = [[0, 0], [0, 0]]
    for r in range(2):
        for c in range(2):
            y = s[r][c] & 0xF
            out[r][c] = (SBOX_INV[y ^ kmask] ^ kmask) & 0xF
    return out

# ---------- Enhanced Encrypt / Decrypt ----------
def encrypt_saes_enhanced(plaintext16: int, key16: int) -> int:
    """
    Enhanced S-AES:
    - Same structure as baseline
    - But SubNib in BOTH rounds uses per-round key-dependent dynamic S-Box.
    """
    k0, k1, k2 = key_expand(key16)

    # masks derived from round keys (impressive + strong)
    m1 = mask_from_round_key(k1)
    m2 = mask_from_round_key(k2)

    s = state_from_u16(plaintext16)
    s = xor_state(s, round_key_state(k0))

    # round 1
    s = sub_nib_dynamic(s, m1)
    s = shift_rows(s)
    s = mix_columns(s)
    s = xor_state(s, round_key_state(k1))

    # round 2 (final)
    s = sub_nib_dynamic(s, m2)
    s = shift_rows(s)
    s = xor_state(s, round_key_state(k2))

    return u16_from_state(s)

def decrypt_saes_enhanced(ciphertext16: int, key16: int) -> int:
    """
    Decrypt for Enhanced S-AES (matches encrypt changes).
    """
    k0, k1, k2 = key_expand(key16)

    m1 = mask_from_round_key(k1)
    m2 = mask_from_round_key(k2)

    s = state_from_u16(ciphertext16)

    # inverse of final round
    s = xor_state(s, round_key_state(k2))
    s = inv_shift_rows(s)
    s = inv_sub_nib_dynamic(s, m2)

    # inverse of round 1
    s = xor_state(s, round_key_state(k1))
    s = inv_mix_columns(s)
    s = inv_shift_rows(s)
    s = inv_sub_nib_dynamic(s, m1)

    # inverse of initial addroundkey
    s = xor_state(s, round_key_state(k0))
    return u16_from_state(s)

# ---------- Quick self-test ----------
def self_test():
    tests = [
        (0x1234, 0x3A94),
        (0x0000, 0x0000),
        (0xFFFF, 0x1A2B),
        (0xBEEF, 0xCAFE),
        (0x0F0F, 0x00F1),
        (0xAAAA, 0x5555),
    ]
    for p, k in tests:
        c = encrypt_saes_enhanced(p, k)
        p2 = decrypt_saes_enhanced(c, k)
        assert p2 == (p & 0xFFFF), f"FAIL: p={p:04X}, k={k:04X}, c={c:04X}, got={p2:04X}"
    print("Enhanced S-AES self_test OK ✅")

if __name__ == "__main__":
    self_test()
