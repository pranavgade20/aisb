# %%

import os
import sys
from typing import Generator, List, Tuple, Callable
# import numpy as np

# Allow imports from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from aisb_utils import report

# %%


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
    # TODO: Implement the LCG keystream generator
    #    - Update state using the LCG formula
    #    - Yield the lowest 8 bits of state as a byte

    a = 1664525
    c = 1013904223
    m = 2**32
    while True:
        seed = (a * seed + c) % m
        seed = seed & 0xFF
        yield seed


from w1d1_test import test_lcg_keystream


test_lcg_keystream(lcg_keystream)


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
    # TODO: Implement stream cipher encryption
    #   - XOR each byte of plaintext with the bytes from lcg_keystream
    #   - return the resulting ciphertext as bytes
    keystream = lcg_keystream(seed)
    return bytes(byte ^ next(keystream) for byte in plaintext)


from w1d1_test import test_encrypt


test_encrypt(lcg_encrypt)


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
    out = 0
    for i, src in enumerate(table):
        # Extract bit from source position
        bit = (value >> (in_width - 1 - src)) & 1
        # Place it at destination position
        out |= bit << (len(table) - 1 - i)
    return out


from w1d1_test import test_permute_expand


# Run the test
test_permute_expand(permute_expand)

# %%
import random
from typing import List

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
    # TODO: Implement key schedule
    #    - Apply P10 permutation
    #    - Split into 5-bit halves
    #    - Generate K1
    #       - Left shift both halves by 1 (LS-1)
    #       - Combine and apply P8
    #    - Generate K2
    #       - Left shift both halves by 2 (LS-2, for total LS-3)
    #       - Combine and apply P8
    #    - you might want to implement left_shift as a helper function
    #       - for example, left_shift 0b10101 by 1 gives 0b01011

    # step 1 Apply P10 permutation
    permutation = permute_expand(key, p10, 10)

    # step 2 Split into 5-bit halves
    left_side = 0
    for i in range(5):
        bit = (permutation >> (10 - 1 - i)) & 1
        left_side |= bit << (5 - 1 - i)

    right_side = 0
    for i in range(5, 10):
        bit = (permutation >> (10 - 1 - i)) & 1
        right_side |= bit << (10 - 1 - i)

    # Left shift both halves by 1 (LS-1)
    left_shifted = left_side << 1
    right_shifted = right_side << 1

    # Combine and apply P8
    combined = 0
    for i in range(5):
        bit = (left_shifted >> (5 - 1 - i)) & 1
        combined |= bit << (5 - 1 - i)
    for i in range(5):
        bit = (right_shifted >> (5 - 1 - i)) & 1
        combined |= bit << (10 - 1 - i)

    # step 3 Generate K1
    K1 = permute_expand(combined, p8, 10)

    # Left shift both halves by 3 (LS-3)
    left_shifted = left_shifted << 2
    right_shifted = right_shifted << 2

    # Combine and apply P8
    combined = 0
    for i in range(5):
        bit = (left_shifted >> (5 - 1 - i)) & 1
        combined |= bit << (5 - 1 - i)
    for i in range(5):
        bit = (right_shifted >> (5 - 1 - i)) & 1
        combined |= bit << (10 - 1 - i)

    # step 3 Generate K1
    K2 = permute_expand(combined, p8, 10)

    return K1, K2

    # def left_shift(value: int, n: int, width: int) -> int:
    #     n %= width  # Handle shifts larger than width
    #     mask = (1 << width) - 1
    #     # Shift left and mask to width, OR with wrapped bits
    #     return ((value << n) & mask) | (value >> (width - n))

    # # Step 1: Initial permutation
    # perm = permute_expand(key, p10, 10)

    # # Step 2: Split into halves
    # left = perm >> 5  # Upper 5 bits
    # right = perm & 0x1F  # Lower 5 bits (0x1F = 0b11111)

    # # Step 3: First shift (LS-1)
    # left = left_shift(left, 1, 5)
    # right = left_shift(right, 1, 5)

    # # Step 4: Generate K1
    # k1 = permute_expand((left << 5) | right, p8, 10)

    # # Step 5: Second shift (LS-2, total LS-3)
    # left = left_shift(left, 2, 5)
    # right = left_shift(right, 2, 5)

    # # Step 6: Generate K2
    # k2 = permute_expand((left << 5) | right, p8, 10)

    # return k1, k2


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
    # TODO: Implement S-box lookup
    print(bits)

    row = 0

    column = 0
    bitlist = []
    for i in range(4):
        bitlist.append((bits >> (4 - 1 - i)) & 1)

    row |= bitlist[0] << 1
    row |= bitlist[3]
    column |= bitlist[1] << (1)
    column |= bitlist[2]
    print("row")
    print(row)
    print(column)
    print(sbox)

    return sbox[row][column]

    pass


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
    expanded = permute_expand(right, ep, 4)  # step 1, expanded is 8 bits
    # step 2
    xor = expanded ^ subkey
    left_side = 0
    for i in range(4):
        bit = (xor >> (8 - 1 - i)) & 1
        left_side |= bit << (4 - 1 - i)

    right_side = 0
    for i in range(4, 8):
        bit = (xor >> (8 - 1 - i)) & 1
        right_side |= bit << (8 - 1 - i)

    # step 4

    # TODO: Implement Feistel function
    #    - Expand right using E/P
    #    - XOR with subkey
    #    - Apply S-boxes to each half
    #    - Combine outputs and apply P4
    #    - XOR with left to get new left
    pass


from w1d1_test import test_feistel


# Run the test
test_feistel(sbox_lookup, fk, EP, S0, S1, P4)
