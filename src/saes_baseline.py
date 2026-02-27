# src/saes_baseline.py
from dataclasses import dataclass
from typing import List, Tuple

SBOX = [0x9,0x4,0xA,0xB,0xD,0x1,0x8,0x5,0x6,0x2,0x0,0x3,0xC,0xE,0xF,0x7]
SBOX_INV = [0xA,0x5,0x9,0xB,0x1,0x7,0x8,0xF,0x6,0x0,0x2,0x3,0xC,0x4,0xD,0xE]

# Round constants (standard S-AES)
RCON1 = 0x80
RCON2 = 0x30

# ---- helpers: nibble/word conversions ----
def split_nibbles16(x: int) -> List[int]:
    """16-bit -> [n0,n1,n2,n3] high to low nibbles"""
    return [(x >> 12) & 0xF, (x >> 8) & 0xF, (x >> 4) & 0xF, x & 0xF]

def join_nibbles16(ns: List[int]) -> int:
    """[n0,n1,n2,n3] -> 16-bit"""
    return ((ns[0] & 0xF) << 12) | ((ns[1] & 0xF) << 8) | ((ns[2] & 0xF) << 4) | (ns[3] & 0xF)

def state_from_u16(x: int) -> List[List[int]]:
    """
    16-bit -> 2x2 nibbles:
    [ [n0, n1],
      [n2, n3] ]
    """
    n0, n1, n2, n3 = split_nibbles16(x)
    return [[n0, n1],[n2, n3]]

def u16_from_state(s: List[List[int]]) -> int:
    return join_nibbles16([s[0][0], s[0][1], s[1][0], s[1][1]])

def xor_state(s: List[List[int]], k: List[List[int]]) -> List[List[int]]:
    return [[(s[r][c] ^ k[r][c]) & 0xF for c in range(2)] for r in range(2)]

# ---- GF(2^4) arithmetic with m(x)=x^4 + x + 1 (0b10011) ----
def gf16_mul(a: int, b: int) -> int:
    """Multiply in GF(2^4) with modulus x^4 + x + 1 (0x13)."""
    a &= 0xF
    b &= 0xF
    p = 0
    for _ in range(4):
        if b & 1:
            p ^= a
        carry = a & 0x8
        a = (a << 1) & 0xF
        if carry:
            a ^= 0x3  # because (x^4 == x + 1) => reduce by 0b0011
        b >>= 1
    return p & 0xF

# ---- core steps ----
def sub_nib(s: List[List[int]]) -> List[List[int]]:
    return [[SBOX[s[r][c]] for c in range(2)] for r in range(2)]

def inv_sub_nib(s: List[List[int]]) -> List[List[int]]:
    return [[SBOX_INV[s[r][c]] for c in range(2)] for r in range(2)]

def shift_rows(s: List[List[int]]) -> List[List[int]]:
    # 2x2: swap bottom row
    return [s[0][:], [s[1][1], s[1][0]]]

def inv_shift_rows(s: List[List[int]]) -> List[List[int]]:
    # same as shift for 2x2
    return [s[0][:], [s[1][1], s[1][0]]]

def mix_columns(s: List[List[int]]) -> List[List[int]]:
    # matrix [[1,4],[4,1]] over GF(16)
    a, b = s[0][0], s[1][0]
    c, d = s[0][1], s[1][1]

    s00 = a ^ gf16_mul(0x4, b)
    s10 = gf16_mul(0x4, a) ^ b
    s01 = c ^ gf16_mul(0x4, d)
    s11 = gf16_mul(0x4, c) ^ d
    return [[s00 & 0xF, s01 & 0xF],[s10 & 0xF, s11 & 0xF]]

def inv_mix_columns(s: List[List[int]]) -> List[List[int]]:
    # inverse matrix for [[1,4],[4,1]] is [[9,2],[2,9]] in GF(16) for standard S-AES
    a, b = s[0][0], s[1][0]
    c, d = s[0][1], s[1][1]

    s00 = gf16_mul(0x9, a) ^ gf16_mul(0x2, b)
    s10 = gf16_mul(0x2, a) ^ gf16_mul(0x9, b)
    s01 = gf16_mul(0x9, c) ^ gf16_mul(0x2, d)
    s11 = gf16_mul(0x2, c) ^ gf16_mul(0x9, d)
    return [[s00 & 0xF, s01 & 0xF],[s10 & 0xF, s11 & 0xF]]

# ---- key expansion ----
def rot_nib(byte: int) -> int:
    return ((byte << 4) | (byte >> 4)) & 0xFF

def sub_nib_byte(byte: int) -> int:
    hi = SBOX[(byte >> 4) & 0xF]
    lo = SBOX[byte & 0xF]
    return ((hi << 4) | lo) & 0xFF

def key_expand(key16: int) -> Tuple[int,int,int]:
    """
    Standard S-AES key expansion:
    key16 -> round keys K0, K1, K2 (each 16-bit)
    """
    w0 = (key16 >> 8) & 0xFF
    w1 = key16 & 0xFF

    w2 = w0 ^ (sub_nib_byte(rot_nib(w1)) ^ RCON1)
    w3 = w2 ^ w1

    w4 = w2 ^ (sub_nib_byte(rot_nib(w3)) ^ RCON2)
    w5 = w4 ^ w3

    k0 = ((w0 << 8) | w1) & 0xFFFF
    k1 = ((w2 << 8) | w3) & 0xFFFF
    k2 = ((w4 << 8) | w5) & 0xFFFF
    return k0, k1, k2

def round_key_state(k16: int) -> List[List[int]]:
    return state_from_u16(k16)

# ---- encrypt/decrypt ----
def encrypt_saes(plaintext16: int, key16: int) -> int:
    k0, k1, k2 = key_expand(key16)
    s = state_from_u16(plaintext16)

    s = xor_state(s, round_key_state(k0))

    # round 1
    s = sub_nib(s)
    s = shift_rows(s)
    s = mix_columns(s)
    s = xor_state(s, round_key_state(k1))

    # round 2 (final)
    s = sub_nib(s)
    s = shift_rows(s)
    s = xor_state(s, round_key_state(k2))

    return u16_from_state(s)

def decrypt_saes(ciphertext16: int, key16: int) -> int:
    k0, k1, k2 = key_expand(key16)
    s = state_from_u16(ciphertext16)

    s = xor_state(s, round_key_state(k2))
    s = inv_shift_rows(s)
    s = inv_sub_nib(s)

    s = xor_state(s, round_key_state(k1))
    s = inv_mix_columns(s)
    s = inv_shift_rows(s)
    s = inv_sub_nib(s)

    s = xor_state(s, round_key_state(k0))
    return u16_from_state(s)

# ---- quick self-test ----
def self_test():
    tests = [
        (0x1234, 0x3A94),
        (0x0000, 0x0000),
        (0xFFFF, 0x1A2B),
        (0xBEEF, 0xCAFE),
    ]
    for p, k in tests:
        c = encrypt_saes(p, k)
        p2 = decrypt_saes(c, k)
        assert p2 == (p & 0xFFFF), f"FAIL: p={p:04X}, k={k:04X}, c={c:04X}, got={p2:04X}"
    print("Baseline S-AES self_test OK ✅")

if __name__ == "__main__":
    self_test()
