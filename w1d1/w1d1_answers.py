# %%

import os
import sys
from typing import Generator, List, Tuple, Callable

# Allow imports from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from aisb_utils import report
# %%
from typing import Generator


def lcg_keystream(seed: int) -> Generator[int, None, None]:
    """
    Generate an infinite keystream using a basic LCG.

    The LCG formula is: next_state = (a * current_state + c) mod m
    Where:
        - a = 1664525
        - c = 1013904223
        - m = 2^32

    Args:
        seed: Initial seed value for the generator.

    Yields:
        Bytes of the keystream as integers in range 0-255.
    """
    current_state = seed
    a = 1664525
    c= 1013904223
    m = 2**32
    while True:
        next_state = (a * current_state + c) % m
        current_state = next_state
        yield next_state & 0xFF

from w1d1_test import test_lcg_keystream


test_lcg_keystream(lcg_keystream)
# %%
def lcg_encrypt(seed: int, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext using the LCG keystream.

    Stream cipher encryption: ciphertext = plaintext XOR keystream

    Args:
        seed: Seed for the keystream generator.
        plaintext: Data to encrypt.

    Returns:
        Ciphertext as bytes.
    """
    keystream = lcg_keystream(seed)
    ciphertext = []
    for c in plaintext:
        k = next(keystream)
        ciphertext.append(c ^ k)

    return bytes(ciphertext)

from w1d1_test import test_encrypt


test_encrypt(lcg_encrypt)


# %%
def lcg_decrypt(seed: int, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext using the same LCG keystream.

    In stream ciphers, decryption is the same operation as encryption!

    Args:
        seed: Seed for the keystream generator.
        ciphertext: Data to decrypt.

    Returns:
        Decrypted plaintext.
    """
    keystream = lcg_keystream(seed)
    plaintext = []
    for c in ciphertext:
        k = next(keystream)
        plaintext.append(c ^ k)

    return bytes(plaintext)

from w1d1_test import test_decrypt


test_decrypt(lcg_decrypt)
from w1d1_test import test_stream_cipher


test_stream_cipher(lcg_keystream, lcg_encrypt, lcg_decrypt)





# %%
import random
from typing import List, Tuple

_params_rng = random.Random(0)
P10 = list(range(10))
_params_rng.shuffle(P10)

_p8_idx = list(range(10))
_params_rng.shuffle(_p8_idx)
P8 = _p8_idx[:8]

IP = list(range(8))
_params_rng.shuffle(IP)
IP_INV = [IP.index(i) for i in range(8)]

EP = [_params_rng.randrange(4) for _ in range(8)]
P4 = list(range(4))
_params_rng.shuffle(P4)

S0 = [[_params_rng.randrange(4) for _ in range(4)] for _ in range(4)]
S1 = [[_params_rng.randrange(4) for _ in range(4)] for _ in range(4)]

# %%
def permute_expand(value: int, table: List[int], in_width: int) -> int:
    """
    Apply a permutation table to rearrange bits. Note that the bits are numbered from left to right (MSB first).

    Args:
        value: Integer containing the bits to permute
        table: List where table[i] is the source position for output bit i
        in_width: Number of bits in the input value

    Returns:
        Integer with bits rearranged according to table

    Example:
        permute(0b1010, [2, 0, 3, 1], 4) = 0b1100
        Because:
        - Output bit 0 comes from input bit 2 (which is 1)
        - Output bit 1 comes from input bit 0 (which is 1)
        - Output bit 2 comes from input bit 3 (which is 0)
        - Output bit 3 comes from input bit 1 (which is 0)
    """
    # TODO: Implement permutation
    #    - For each position i in the output
    #    - Get the source bit position from table[i]
    #    - Extract that bit from the input
    #    - Place it at position i in the output
    permuted = 0
    target_len = len(table)

    for i in range(target_len):
        pos = table[i]
        value_bit = (value >> (in_width - pos - 1)) & 1
        permuted |= (value_bit << (target_len - i - 1))

    return permuted
# %%
from w1d1_test import test_permute_expand


# Run the test
test_permute_expand(permute_expand)

#%%
# For example, left_shift 0b10101 by 1 gives 0b01011
def left_shift(num: int, num_len: int, shift_by: int) -> int:
    return ((num << shift_by) % (1 << num_len)) | (num >> (num_len - shift_by))
# %%
def key_schedule(key: int, p10: List[int], p8: List[int]) -> Tuple[int, int]:
    """
    Generate two 8-bit subkeys from a 10-bit key.

    Process:
    1. Apply P10 permutation to the key
    2. Split into left (5 bits) and right (5 bits) halves
    3. Circular left shift both halves by 1 - to get left_half and right_half
    4. Combine the halves and apply P8 to get K1
    5. Circular left shift left_half and right_half (the halves before applying P8) by 2 more (total shift of 3)
    6. Combine the halves and apply P8 to get K2

    Args:
        key: 10-bit encryption key
        p10: Initial permutation table (10 → 10 bits)
        p8: Selection permutation table (10 → 8 bits)

    Returns:
        Tuple of (K1, K2) - the two 8-bit subkeys
    """
    # Steps:
    #    - Apply P10 permutation
    key_p10 = permute_expand(key, p10, 10)
    #    - Split into 5-bit halves
    left_raw = key_p10 & (31 << 5)
    right_raw = key_p10 & 31
    #    - Generate K1
    #       - Left shift both halves by 1 (LS-1)
    left_half_1 = left_shift(left_raw, 5, 1)
    right_half_1 = left_shift(right_raw, 5, 1)
    #       - Combine and apply P8
    combined_lr_1 = (left_half_1 << 5) | right_half_1
    k1 = permute_expand(combined_lr_1, p8, 10)
    #    - Generate K2
    #       - Left shift both halves by 2 (LS-2, for total LS-3)
    left_half_2 = left_shift(left_raw, 5, 3)
    right_half_2 = left_shift(right_raw, 5, 3)
    #       - Combine and apply P8
    combined_lr_2 = (left_half_2 << 5) | right_half_2
    k2 = permute_expand(combined_lr_2, p8, 10)

    return k1, k2

from w1d1_test import test_key_schedule


# Run the test
test_key_schedule(key_schedule, P10, P8)


# %%
def sbox_lookup(sbox: List[List[int]], bits: int) -> int:
    """
    Look up a value in an S-box.

    DES S-boxes are 4x4 tables accessed by:
    - Row: bit 0 (MSB) and bit 3 (LSB) form a 2-bit row index
    - Column: bits 1 and 2 form a 2-bit column index

    Args:
        sbox: 4x4 table of 2-bit values
        bits: 4-bit input (only lower 4 bits used)

    Returns:
        2-bit output from S-box

    Example:
        For input 0b1010:
        - Row = b0,b3 = 1,0 = 2
        - Col = b1,b2 = 0,1 = 1
        - Output = sbox[2][1]
    """
    b3 = bits & 1
    b2 = (bits >> 1) & 1
    b1 = (bits >> 2) & 1
    b0 = (bits >> 3) & 1

    row = (b0 << 1) | b3
    col = (b1 << 1) | b2

    return sbox[row][col]

from w1d1_test import test_sbox_lookup


test_sbox_lookup(sbox_lookup, S0, S1)
# %%


def fk(
    left: int, right: int, subkey: int, ep: List[int], s0: List[List[int]], s1: List[List[int]], p4: List[int]
) -> Tuple[int, int]:
    """
    Apply the Feistel function to one round of DES.

    Process:
    1. Expand right half from 4 to 8 bits using E/P
    2. XOR with subkey
    3. Split into two 4-bit halves
    4. Apply S0 to left half, S1 to right half
    5. Combine S-box outputs and permute with P4
    6. XOR result with left half

    Args:
        left: 4-bit left half
        right: 4-bit right half
        subkey: 8-bit round key
        ep: Expansion permutation table (4 → 8 bits)
        s0: First S-box (4x4)
        s1: Second S-box (4x4)
        p4: Final permutation (4 → 4 bits)

    Returns:
        Tuple of (new_left, right) - right is unchanged
    """
    #    - Expand right using E/P
    right_exp = permute_expand(right, ep, 4)
    #    - XOR with subkey
    right_xor = right_exp ^ subkey
    #    - Apply S-boxes to each half
    rr = right_xor & 15
    rl = (right_xor >> 4) & 15

    rl_sbox = sbox_lookup(s0, rl)
    rr_sbox = sbox_lookup(s1, rr)
    #    - Combine outputs and apply P4
    r_combined = (rl << 15) | rr
    r_p4 = permute_expand(r_combined, p4, 4)
    #    - XOR with left to get new left
    new_left = left ^ r_p4

    return new_left, right
    
from w1d1_test import test_feistel


# Run the test
test_feistel(sbox_lookup, fk, EP, S0, S1, P4)
# %%
