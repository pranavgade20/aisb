# %%

import os
import sys
from turtle import left
from typing import Generator, List, Tuple, Callable

import tqdm

# %%
# Allow imports from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from aisb_utils import report

from typing import Generator

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
    if seed is None:
        return

    X_N = seed
    while True:
        X_N = (1664525 * X_N + 1013904223) % 2**32
        X_N = X_N & 0xFF

        yield X_N

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
    # TODO: Implement stream cipher encryption
    #   - XOR each byte of plaintext with the bytes from lcg_keystream
    #   - return the resulting ciphertext as bytes
    
    keystream = lcg_keystream(seed)
    cyphertext = [next(keystream) for i in range(len(plaintext))]
    cyphertext = bytes(cyphertext)

    return bytes(c ^ p for c, p in zip(cyphertext, plaintext))

from w1d1_test import test_encrypt

test_encrypt(lcg_encrypt)

# %%
test = b'test string'
print(test)


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
    # TODO: Implement stream cipher decryption
    
    keystream = lcg_keystream(seed)
    cyphertext = [next(keystream) for i in range(len(ciphertext))]
    cyphertext = bytes(cyphertext)

    return bytes(c ^ p for c, p in zip(cyphertext, ciphertext))

from w1d1_test import test_decrypt


test_decrypt(lcg_decrypt)
from w1d1_test import test_stream_cipher


test_stream_cipher(lcg_keystream, lcg_encrypt, lcg_decrypt)

# %%

def recover_lcg_state(keystream_bytes: list[int]) -> int:
    """
    Recover the LCG seed from consecutive keystream bytes.

    The key insight is that we observe the OUTPUT of states, not the states themselves.
    If we see byte b0, that was produced by some state s0.
    We need to find s_{-1} (the seed) such that s0 = (a * s_{-1} + c) % m and s0 & 0xFF = b0.

    Args:
        keystream_bytes: At least 2 consecutive bytes from the keystream.

    Returns:
        A seed (initial state) that generates this keystream.
    """
    if len(keystream_bytes) < 2:
        raise ValueError("Need at least 2 keystream bytes")

    a = 1664525
    c = 1013904223
    m = 2**32
    # TODO: Implement LCG state recovery
    #   - brute-force through all possible upper 24 bits - this will let you try all possible starting states
    #   - for each state, check if it produces the correct bytes
    #   - if it does, calculate the seed by rearranging the LCG formula to get a formula for the seed
    for i in tqdm.tqdm(range(2**24)):
        keystream = lcg_keystream(i)

        broken = False
        for j in range(len(keystream_bytes)):
            nextval = next(keystream)
            if nextval != keystream_bytes[j]:
                broken = True
                break

        if not broken:
            return i
    return None


from w1d1_test import test_lcg_state_recovery


test_lcg_state_recovery(lcg_keystream, recover_lcg_state)

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
        permute(0b0110, [2, 0, 3, 1], 4) = 0b1100
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

    # byte_value = value.to_bytes(in_width)
    # out = [0]*in_width

    # for i in range(in_width):
    #     # out.append(byte_value[table[i]])
    #     index = table[i]
    #     bit = (value >> index) & 1
    #     out[i] = (out[i] | bit)

    # out = out[::-1]
    # res = 0
    # for bit in out:
    #     res = (res << 1) | bit

    
    # # return int(bin(res), 2)
    # return res

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

    # step 1
    key = permute_expand(key, p10, 10)
    # step 2
    left_half = key >> 5
    right_half = key & 0b11111
    # step 3
    left_half = ((left_half << 1)|(left_half >> (5 - 1))) & 0b11111
    right_half = ((right_half << 1)|(right_half >> (5 - 1))) & 0b11111
    # step 4
    K1 = (left_half << 5) | right_half
    K1 = permute_expand(K1, p8, 10)
    # step 5
    left_half = ((left_half << 2)|(left_half >> (5 - 2))) & 0b11111
    right_half = ((right_half << 2)|(right_half >> (5 - 2))) & 0b11111
    # step 6
    K2 = (left_half << 5) | right_half
    K2 = permute_expand(K2, p8, 10)

    return K1, K2
    

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
    # get row/col
    bitlist = [
        (bits >> i) & 1
        for i in range(4)
    ]
    bitlist = bitlist[::-1]
    rowlist = [bitlist[0],bitlist[3]]
    collist = [bitlist[1],bitlist[2]]

    row = (rowlist[0] << 1) | rowlist[1]
    col = (collist[0] << 1) | collist[1]

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
    step1 = permute_expand(right, ep, 4)
    step2 = subkey ^ step1

    step3_lhs = step2 >> 4
    step3_rhs = step2 & 0b1111

    step4_lhs = sbox_lookup(s0, step3_lhs)
    step4_rhs = sbox_lookup(s1, step3_rhs)

    step5_1 = (step4_lhs << 4) | step4_rhs
    step5 = permute_expand(step5_1, p4, 8)

    step6 = step5 ^ step4_lhs
    return step6, right



from w1d1_test import test_feistel


# Run the test
test_feistel(sbox_lookup, fk, EP, S0, S1, P4)




def encrypt_byte(
    byte: int,
    k1: int,
    k2: int,
    ip: List[int],
    ip_inv: List[int],
    ep: List[int],
    s0: List[List[int]],
    s1: List[List[int]],
    p4: List[int],
) -> int:
    """
    Encrypt or decrypt a single byte using DES.

    For encryption: use (k1, k2)
    For decryption: use (k2, k1) - reversed order!

    Process:
    1. Apply initial permutation (IP)
    2. Split into 4-bit halves
    3. Apply fk with first key
    4. Swap halves
    5. Apply fk with second key
    6. Combine halves and apply IP⁻¹

    Args:
        byte: 8-bit value to process
        k1: First subkey (8 bits)
        k2: Second subkey (8 bits)
        ip: Initial permutation table
        ip_inv: Inverse initial permutation table
        ep: Expansion permutation for fk
        s0, s1: S-boxes for fk
        p4: Permutation for fk

    Returns:
        8-bit processed value
    """
    # TODO: Implement DES encryption/decryption
    #    - Apply IP
    #    - Two rounds with swap in between
    #    - Apply IP⁻¹
    #    - Same function for encrypt/decrypt!
    pass


def des_encrypt(key: int, plaintext: bytes) -> bytes:
    """Encrypt bytes using DES"""
    k1, k2 = key_schedule(key, P10, P8)
    return bytes(encrypt_byte(b, k1, k2, IP, IP_INV, EP, S0, S1, P4) for b in plaintext)


def des_decrypt(key: int, ciphertext: bytes) -> bytes:
    """Decrypt bytes using DES."""
    k1, k2 = key_schedule(key, P10, P8)
    # Note: reversed key order for decryption!
    return bytes(encrypt_byte(b, k2, k1, IP, IP_INV, EP, S0, S1, P4) for b in ciphertext)
from w1d1_test import test_des_complete


# Run the test
test_des_complete(encrypt_byte, des_encrypt, des_decrypt, key_schedule, P10, P8, IP, IP_INV, EP, S0, S1, P4)