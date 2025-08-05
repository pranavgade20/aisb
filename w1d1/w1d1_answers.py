# %%

import os
import sys
from typing import Callable, Generator, List, Tuple

# Allow imports from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from aisb_utils import report


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
    state = seed
    while True:
        state = (a * state + c) % m
        yield state & 0xFF  # Extract lowest 8 bits as a byte


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
    result: list[int] = []
    keystream = lcg_keystream(seed)
    for byte in plaintext:
        key = next(keystream)
        encrypted = byte ^ key
        result.append(encrypted)

    return bytes(result)


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
    # TODO: Implement stream cipher decryption
    return lcg_encrypt(seed, ciphertext)


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

    for upper_24_bits in range(2**24):
        s_0 = (upper_24_bits << 8) | keystream_bytes[0]

        keystream = lcg_keystream(s_0)
        keys = [next(keystream) for _ in range(len(keystream_bytes) - 1)]
        if keys == keystream_bytes[1:]:
            break

    a_inv = pow(a, -1, m)
    seed = ((s_0 - c) * a_inv) % m
    return seed


from w1d1_test import test_lcg_state_recovery

test_lcg_state_recovery(lcg_keystream, recover_lcg_state)

# %%


from w1d1_stream_cipher_secrets import intercept_messages

ciphertext1, ciphertext2 = intercept_messages(lcg_encrypt)
print(f"Intercepted ciphertext 1 ({len(ciphertext1)} bytes): {ciphertext1[:50].hex()}...")
print(f"Intercepted ciphertext 2 ({len(ciphertext2)} bytes): {ciphertext2[:50].hex()}...")

# %%

import random

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
    # out = 0
    # for output_pos, input_bit in enumerate(table):
    #     # Extract bit from source position
    #     amount_to_shift_value_right = in_width - 1 - input_bit
    #     value_shifted_right = value >> amount_to_shift_value_right
    #     bit = value_shifted_right & 1

    #     # Place it at destination position
    #     amount_to_shift_bit_left = len(table) - 1 - output_pos
    #     bit_shifted_left = bit << amount_to_shift_bit_left
    #     out |= bit_shifted_left

    # return out

    out = 0
    for i, src in enumerate(table):
        # Extract bit from source position
        bit = (value >> (in_width - 1 - src)) & 1
        # Place it at destination position
        out |= bit << (len(table) - 1 - i)
    return out

    # result = 0
    # for output_pos, input_bit in enumerate(table):
    #     print(f"     {value:032b}")
    #     input_bit_pos = 32 - in_width + input_bit
    #     print(f"{input_bit_pos=}")
    #     amount_to_shift = 32 - input_bit_pos - 1
    #     print(f"{amount_to_shift=}")

    #     mask = 1 << amount_to_shift
    #     print(f"       mask={mask:032b}")

    #     input_value = mask & value
    #     print(f"input_value={input_value:032b}")
    #     input_value_shifted = input_value >> amount_to_shift
    #     print(f"    shifted={input_value_shifted:032b}")

    #     amount_to_shift_back = in_width - output_pos - 1
    #     shifted_again = input_value_shifted << amount_to_shift_back

    #     result = result | shifted_again
    #     print(f"     result={result:032b}")
    #     print("===")

    # TODO: Implement permutation
    #    - For each position i in the output
    #    - Get the source bit position from table[i]
    #    - Extract that bit from the input
    #    - Place it at position i in the output
    pass


permute_expand(0b1010, [2, 0, 3, 1], 4)

from w1d1_test import test_permute_expand

# Run the test
test_permute_expand(permute_expand)

# %%


def left_shift(n, d, N):
    return ((n << d) % (1 << N)) | (n >> (N - d))


shifted = left_shift(0b10101, 1, 5)
print(f"{shifted:05b}")

shifted = left_shift(0b1010100000, 1, 5)
print(f"{shifted:05b}")


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
    permuted = permute_expand(key, p10, 10)
    #    - Split into 5-bit halves
    left_half = (0b1111100000 & permuted) >> 5
    right_half = 0b0000011111 & permuted
    #    - Generate K1
    #       - Left shift both halves by 1 (LS-1)
    shifted_left_half = left_shift(left_half, 1, 5)
    shifted_right_half = left_shift(right_half, 1, 5)
    #       - Combine and apply P8
    combined = (shifted_left_half << 5) | shifted_right_half
    K1 = permute_expand(combined, p8, 10)
    #    - Generate K2
    #       - Left shift both halves by 2 (LS-2, for total LS-3)
    shifted_left_half = left_shift(shifted_left_half, 2, 5)
    shifted_right_half = left_shift(shifted_right_half, 2, 5)
    #       - Combine and apply P8
    combined = (shifted_left_half << 5) | shifted_right_half
    K2 = permute_expand(combined, p8, 10)
    #    - you might want to implement left_shift as a helper function
    #       - for example, left_shift 0b10101 by 1 gives 0b01011
    return (K1, K2)


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
    b0 = bits & 0b1000
    b3 = bits & 0b0001
    row = (b0 >> 2) | b3

    b1 = bits & 0b0100
    b2 = bits & 0b0010
    col = (b1 >> 1) | (b2 >> 1)

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
    # TODO: Implement Feistel function
    #    - Expand right using E/P
    right_expanded = permute_expand(right, ep, 4)
    #    - XOR with subkey
    xor_out = right_expanded ^ subkey
    left_half = (0b11110000 & xor_out) >> 4
    right_half = 0b00001111 & xor_out
    #    - Apply S-boxes to each half
    sbox_left_out = sbox_lookup(s0, left_half)
    sbox_right_out = sbox_lookup(s1, right_half)
    #    - Combine outputs and apply P4
    combined = (sbox_left_out << 2) | sbox_right_out
    p4_out = permute_expand(combined, p4, 4)
    #    - XOR with left to get new left
    return left ^ p4_out, right


from w1d1_test import test_feistel

# Run the test
test_feistel(sbox_lookup, fk, EP, S0, S1, P4)


# %%
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
    ip_out = permute_expand(byte, ip, 8)
    left = (ip_out & 0b11110000) >> 4
    right = ip_out & 0b00001111
    #    - Two rounds with swap in between
    left, right = fk(left, right, k1, ep, s0, s1, p4)
    left, right = right, left
    left, right = fk(left, right, k2, ep, s0, s1, p4)
    combined = (left << 4) | right
    #    - Apply IP⁻¹
    ip_inv_out = permute_expand(combined, ip_inv, 8)
    return ip_inv_out


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

# %%


def double_encrypt(key1: int, key2: int, plaintext: bytes) -> bytes:
    """Encrypt twice with different keys."""
    temp = des_encrypt(key1, plaintext)
    return des_encrypt(key2, temp)


def double_decrypt(key1: int, key2: int, ciphertext: bytes) -> bytes:
    """Decrypt twice with different keys (reverse order)."""
    temp = des_decrypt(key2, ciphertext)
    return des_decrypt(key1, temp)


def meet_in_the_middle_attack(plaintext: bytes, ciphertext: bytes) -> List[Tuple[int, int]]:
    """
    Find all key pairs (k1, k2) such that:
    double_encrypt(k1, k2, plaintext) == ciphertext

    Strategy:
    1. Build table: for each k1, compute encrypt(k1, plaintext)
    2. For each k2, compute decrypt(k2, ciphertext)
    3. If decrypt(k2, ciphertext) is in our table, we found a match!

    Args:
        plaintext: Known plaintext
        ciphertext: Corresponding ciphertext from double encryption

    Returns:
        List of (key1, key2) pairs that work
    """
    # TODO: Implement meet-in-the-middle attack
    #    - Build table of all encrypt(k1, plaintext)
    all_keys = list(range(2**10))
    forward_table = {des_encrypt(key, plaintext): key for key in all_keys}
    reverse_table = {des_decrypt(key, ciphertext): key for key in all_keys}

    intersection = forward_table.keys() & reverse_table.keys()

    return [(forward_table[txt], reverse_table[txt]) for txt in intersection]


from w1d1_test import test_meet_in_the_middle

# Run the test
test_meet_in_the_middle(meet_in_the_middle_attack, double_encrypt)


import random
from typing import List


def _generate_sbox(seed: int = 1):
    rng = random.Random(seed)
    sbox = list(range(16))
    rng.shuffle(sbox)
    inv = [0] * 16
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


SBOX, INV_SBOX = _generate_sbox()


def substitute(x: int, sbox: List[int]) -> int:
    """
    Apply S-box substitution to a 16-bit value.

    The 16-bit input is divided into four 4-bit nibbles.
    Each nibble is substituted using the provided S-box.

    Args:
        x: 16-bit integer to substitute
        sbox: List of 16 integers (0-15) defining the substitution

    Returns:
        16-bit integer after substitution
    """
    print(sbox)
    # TODO: Implement S-box substitution
    #    - Extract each 4-bit nibble from x
    first_nibble = (x & 0b1111000000000000) >> 12
    second_nibble = (x & 0b0000111100000000) >> 8
    third_nibble = (x & 0b0000000011110000) >> 4
    fourth_nibble = (x & 0b0000000000001111)


    nibbles = [first_nibble, second_nibble, third_nibble, fourth_nibble]


    substituted_nibbles: list[int] = []
    for nibble in nibbles:
        substituted_nibbles.append(sbox[nibble])
    
    result = 0
    for i, substituted_nibble in enumerate(reversed(substituted_nibbles)):
        to_add = substituted_nibble << (i * 4)
        result |= (substituted_nibble << (i * 4))
    return result



    # for nibble, substitution in zip(nibbles, sbox):
    #     print(f"Nibble={nibble:016b}, Substitution={substitution}")
    #     shifted_nibble = nibble >> (4 * substitution)
    #     print(f"Shifted={shifted_nibble:016b}")
    #     shifted_nibbles.append(shifted_nibble)

    #    - Combine the substituted nibbles into the output
    # result = 0
    # for shifted_nibble in shifted_nibbles:
    #     result |= shifted_nibble

    # return result

from w1d1_test import test_substitute


# Run the test
test_substitute(substitute, SBOX)
