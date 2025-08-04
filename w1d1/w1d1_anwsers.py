# %%

import os
import sys
from tkinter import RIGHT
from typing import Generator, List, Tuple, Callable

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
    state = seed
    while True:
        state = (a * state + c) % m
        out = state & ((2 << 7) - 1)
        yield out
    # print(seed, next_state, out)


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
    out = []
    keystream = lcg_keystream(seed)
    for i in range(len(plaintext)):
        out.append(int(plaintext[i]) ^ next(keystream))
    return bytes(out)


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
    out = []
    keystream = lcg_keystream(seed)
    for i in range(len(ciphertext)):
        out.append(int(ciphertext[i]) ^ next(keystream))
    return bytes(out)


from w1d1_test import test_decrypt


test_decrypt(lcg_decrypt)
from w1d1_test import test_stream_cipher


test_stream_cipher(lcg_keystream, lcg_encrypt, lcg_decrypt)


# %%
import math


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
    # for keyidx in range(len(keystream_bytes[1:])):
    # for keyidx in range(len(keystream_bytes)):
    #     previous_out = keystream_bytes[-keyidx - 1]
    #     current_out = keystream_bytes[-keyidx]
    for uppers in range(1, 2**24):
        s0 = (uppers << 8) | keystream_bytes[0]

        state = s0
        valid = True
        for i in range(1, len(keystream_bytes)):
            state = ((a * state + c) % m) & 0xFF
            if state != keystream_bytes[i]:
                valid = False
                break
        if valid is True:
            print(s0, uppers)
            print(math.gcd(a, m))
            a_inv = pow(a, -1, m)
            print(a_inv)
            seed = ((s0 - c) * a_inv) % m
            print(seed)
            return seed


from w1d1_test import test_lcg_state_recovery


test_lcg_state_recovery(lcg_keystream, recover_lcg_state)

# %%

from w1d1_stream_cipher_secrets import intercept_messages

ciphertext1, ciphertext2 = intercept_messages(lcg_encrypt)
print(f"Intercepted ciphertext 1 ({len(ciphertext1)} bytes): {ciphertext1[:50].hex()}...")
print(f"Intercepted ciphertext 2 ({len(ciphertext2)} bytes): {ciphertext2[:50].hex()}...")

# %%


def crib_drag(ciphertext1: bytes, ciphertext2: bytes, crib: bytes) -> list[tuple[int, bytes]]:
    """
    Perform crib-dragging attack on two ciphertexts encrypted with the same keystream.

    Args:
        ciphertext1: First intercepted ciphertext
        ciphertext2: Second intercepted ciphertext
        crib: Known plaintext fragment to try

    Returns:
        List of (position, recovered_text) tuples for further analysis.
    """
    # TODO: Implement crib-dragging
    #   - Use the xor_texts = C1 XOR C2 to find M1 XOR M2
    #   - For each position in xor_texts, XOR the crib with the text at that position
    #   - return a list of tuples (position, recovered_text)

    # Hint:
    # 1. Calculate xor_texts = C1 XOR C2 (which equals M1 XOR M2)
    # 2. For each position from 0 to len(xor_texts) - len(crib):
    #    a. XOR the crib with xor_texts at this position
    #    b. Check if result is readable (all bytes are printable ASCII: 32-126)
    #    c. If readable, add (position, recovered_text) to results
    # 3. Return results list
    xor_texts = bytes(b1 ^ b2 for b1, b2 in zip(ciphertext1, ciphertext2))
    res = []
    for i in range(len(xor_texts) - len(crib)):
        test = bytes(b1 ^ b2 for b1, b2 in zip(xor_texts[i : i + len(crib)], crib))
        valid = True
        for b in test:
            if b < 32 or b > 126:
                valid = False
                break
        if valid == True:
            print(i, test)
            res.append((i, test))
    return res


from w1d1_test import test_crib_drag


correct_position = test_crib_drag(crib_drag, ciphertext1, ciphertext2)

# %%

# def permute_expand(value: int, table: List[int], in_width: int) -> int:
#     """
#     Apply a permutation table to rearrange bits. Note that the bits are numbered from left to right (MSB first).

#     Args:
#         value: Integer containing the bits to permute
#         table: List where table[i] is the source position for output bit i
#         in_width: Number of bits in the input value

#     Returns:
#         Integer with bits rearranged according to table

#     Example:
#         permute(0b1010, [2, 0, 3, 1], 4) = 0b1100
#         Because:
#         - Output bit 0 comes from input bit 2 (which is 1)
#         - Output bit 1 comes from input bit 0 (which is 1)
#         - Output bit 2 comes from input bit 3 (which is 0)
#         - Output bit 3 comes from input bit 1 (which is 0)
#     """
#     # TODO: Implement permutation
#     #    - For each position i in the output
#     #    - Get the source bit position from table[i]
#     #    - Extract that bit from the input
#     #    - Place it at position i in the output
#     output = 0
#     for i in range(len(table)):
#         original_bit_value = int(bool(value & (1 << table[i])))
#         output = output | (original_bit_value << i)
#     return output


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
    if "SOLUTION":
        out = 0
        for i, src in enumerate(table):
            # Extract bit from source position
            bit = (value >> (in_width - 1 - src)) & 1
            # Place it at destination position
            out |= bit << (len(table) - 1 - i)
        return out
    else:
        # TODO: Implement permutation
        #    - For each position i in the output
        #    - Get the source bit position from table[i]
        #    - Extract that bit from the input
        #    - Place it at position i in the output
        pass


# # print(permute_expand(0b1010, [2, 0, 3, 1], 4))
# compression = [1, 3, 4, 6, 7, 9]  # 10 bits → 6 bits (select 6 from 10)
# result = permute_expand(0b1010101010, compression, 10)
# assert result == 0b001100

from w1d1_test import test_permute_expand

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
    # 1
    permuted = permute_expand(key, p10, 10)
    # 2
    first_half = permuted & (0b11111 << 5)
    second_half = (permuted >> 5) & 0b11111
    # 3
    left_half = (first_half << 1) | (first_half >> 5 - 1)
    right_half = (second_half << 1) | (second_half >> 5 - 1)
    # 4
    full = left_half | (right_half << 5)
    k1 = permute_expand(full, p8, 10)
    # 5
    left_half = (first_half << 3) | (first_half >> 5 - 3)
    right_half = (second_half << 3) | (second_half >> 5 - 3)
    # 6
    full = left_half | (right_half << 5)
    k2 = permute_expand(full, p8, 10)
    return (k1, k2)


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
    # # TODO: Implement S-box lookup
    # bits = bits & 0b1111
    # row_idx = (bits & 0b1) | (((bits & 0b1000) >> 3) << 1)
    # col_idx = ((bits & 0b10) >> 1) | (((bits & 0b100) >> 2) << 1)
    # return sbox[row_idx][col_idx] & 0b11
    row = ((bits >> 3) & 1) << 1 | (bits & 1)
    # Extract column from bits 1 and 2
    col = ((bits >> 2) & 1) << 1 | ((bits >> 1) & 1)
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
    #    - XOR with subkey
    #    - Apply S-boxes to each half
    #    - Combine outputs and apply P4
    #    - XOR with left to get new left
    # step1 = permute_expand(right, ep, 4)
    # step2 = subkey ^ step1
    # step3_left = step2 & 0b1111
    # step3_right = (step2 >> 4) & 0b1111
    # step4_left = sbox_lookup(s0, step3_left)
    # step4_right = sbox_lookup(s1, step3_right)
    # step5_full = step4_left | (step4_right << 4)
    # step5_permuted = permute_expand(step5_full, p4, 4)
    # step6 = step5_permuted ^ left
    # return (step6, right)
    expanded = permute_expand(right, ep, 4)

    # Step 2: XOR with subkey

    expanded ^= subkey

    # Step 3: Split for S-boxes
    left_half = expanded >> 4  # Upper 4 bits
    right_half = expanded & 0xF  # Lower 4 bits

    # Step 4: S-box substitution
    s0_out = sbox_lookup(s0, left_half)
    s1_out = sbox_lookup(s1, right_half)

    # Step 5: Combine and permute
    combined = (s0_out << 2) | s1_out  # S0 output is upper 2 bits
    p4_out = permute_expand(combined, p4, 4)

    # Step 6: XOR with left half
    new_left = left ^ p4_out

    return new_left, right


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
    #    - Two rounds with swap in between
    #    - Apply IP⁻¹
    #    - Same function for encrypt/decrypt!
    # bits = permute_expand(byte, ip, 8)
    # left = (bits >> 4) & 0b1111
    # right = bits & 0b1111
    # left, right = fk(left, right, k1, ep, s0, s1, p4)
    # left, right = right, left
    # left, right = fk(left, right, k2, ep, s0, s1, p4)
    # step6 = (left << 4) | right
    # out = permute_expand(step6, ip_inv, 8)
    # return out
    bits = permute_expand(byte, ip, 8)

    # Step 2: Split into halves
    left = bits >> 4  # Upper 4 bits
    right = bits & 0xF  # Lower 4 bits

    # Step 3: First round
    left, right = fk(left, right, k1, ep, s0, s1, p4)

    # Step 4: Swap
    left, right = right, left

    # Step 5: Second round
    left, right = fk(left, right, k2, ep, s0, s1, p4)

    # Step 6: Combine and final permutation
    combined = (left << 4) | right
    result = permute_expand(combined, ip_inv, 8)

    return result


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

from typing import List
import random


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
    # TODO: Implement S-box substitution
    #    - Extract each 4-bit nibble from x
    #    - Look up the substitution for each nibble in sbox
    #    - Combine the substituted nibbles into the output
    out = 0
    n0 = x >> 0 & 0b1111
    n1 = x >> 4 & 0b1111
    n2 = x >> 8 & 0b1111
    n3 = x >> 12 & 0b1111
    out = sbox[n0] | (sbox[n1] << 4) | (sbox[n2] << 8) | (sbox[n3] << 12)
    return out
    # out = 0
    # for i in range(4):
    #     nib = (x >> (i * 4)) & 0xF
    #     out |= sbox[nib] << (i * 4)
    # return out
    # pass


from w1d1_test import test_substitute

test_substitute(substitute, SBOX)

# %%


def _generate_pbox(seed: int = 2):
    rng = random.Random(seed)
    pbox = list(range(16))
    rng.shuffle(pbox)
    inv = [0] * 16
    for i, p in enumerate(pbox):
        inv[p] = i
    return pbox, inv


PBOX, INV_PBOX = _generate_pbox()


def permute(x: int, pbox: List[int]) -> int:
    """
    Apply P-box permutation to a 16-bit value.

    For each output bit position i, take the bit from input position pbox[i].

    Args:
        x: 16-bit integer to permute
        pbox: List of 16 integers (0-15) defining the permutation
              pbox[i] = j means output bit i comes from input bit j

    Returns:
        16-bit integer after permutation
    """
    # TODO: Implement P-box permutation
    #    - For each output position i (0 to 15)
    #    - Get the input bit from position pbox[i]
    #    - Place it at output position i
    out = 0
    print(x, pbox)
    for i in range(16):
        bits = (x >> pbox[i]) & 1
        out |= bits << i
    print(out)
    # return out
    out = 0
    for i, p in enumerate(pbox):
        bit = (x >> (15 - p)) & 1
        out |= bit << (15 - i)
    print(out)
    return out


from w1d1_test import test_permute

test_permute(permute, PBOX)

# %%


def round_keys(key: int) -> List[int]:
    """Generate round keys from the main key."""
    import random

    rng = random.Random(key)
    return [rng.randrange(0, 1 << 16) for _ in range(3)]


def encrypt_block(block: int, keys: List[int], sbox: List[int], pbox: List[int]) -> int:
    """
    Encrypt a single 16-bit block using the SPN cipher.

    The cipher consists of:
    1. XOR with key[0]
    2. S-box substitution
    3. P-box permutation
    4. XOR with key[1]
    5. S-box substitution
    6. P-box permutation
    7. XOR with key[2]

    Args:
        block: 16-bit integer to encrypt
        keys: List of 3 round keys
        sbox: S-box for substitution
        pbox: P-box for permutation

    Returns:
        16-bit encrypted block
    """
    # TODO: Implement the encryption algorithm
    #    - Start with XOR of block and keys[0]
    #    - Apply S-box substitution and P-box permutation
    #    - XOR with keys[1]
    #    - Apply S-box substitution and P-box permutation again
    #    - End with XOR of keys[2]
    # one = keys[0] ^ block
    # two = substitute(one, sbox)
    # three = permute(two, pbox)
    # four = keys[1] ^ three
    # five = substitute(four, sbox)
    # six = permute(five, pbox)
    # seven = keys[2] ^ six
    # return seven
    x = block ^ keys[0]
    x = substitute(x, sbox)
    x = permute(x, pbox)
    x = x ^ keys[1]
    x = substitute(x, sbox)
    x = permute(x, pbox)
    x = x ^ keys[2]
    return x


def decrypt_block(block: int, keys: List[int], inv_sbox: List[int], inv_pbox: List[int]) -> int:
    """
    Decrypt a single 16-bit block using the SPN cipher.

    Decryption reverses the encryption process:
    1. XOR with key[2]
    2. Inverse P-box permutation
    3. Inverse S-box substitution
    4. XOR with key[1]
    5. Inverse P-box permutation
    6. Inverse S-box substitution
    7. XOR with key[0]

    Args:
        block: 16-bit integer to decrypt
        keys: List of 3 round keys (same as encryption)
        inv_sbox: Inverse S-box for substitution
        inv_pbox: Inverse P-box for permutation

    Returns:
        16-bit decrypted block
    """
    # one = keys[2] ^ block
    # two = permute(one, inv_pbox)
    # three = substitute(two, inv_sbox)
    # four = keys[1] ^ three
    # five = permute(four, inv_pbox)
    # six = substitute(five, inv_sbox)
    # seven = keys[0] ^ six
    # return seven
    x = block ^ keys[2]
    x = permute(x, inv_pbox)
    x = substitute(x, inv_sbox)
    x = x ^ keys[1]
    x = permute(x, inv_pbox)
    x = substitute(x, inv_sbox)
    x = x ^ keys[0]
    return x
    # TODO: Implement the decryption algorithm
    #    - Reverse the encryption steps
    #    - Use inverse S-box and P-box
    #    - Apply keys in reverse order


from w1d1_test import test_block_cipher


# Run the test
test_block_cipher(encrypt_block, decrypt_block, round_keys, SBOX, PBOX, INV_SBOX, INV_PBOX)
