# %%

import os
import sys
from typing import Generator, List, Tuple, Callable

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

    current_state = seed
    while True:
        current_state = (a * current_state + c) % m
        yield current_state & 0xFF


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

    byte_list = []
    for byte, code in zip(plaintext, lcg_keystream(seed=seed)):
        byte_list.extend([byte ^ code])

    return bytes(byte_list)


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
    byte_list = []
    for byte, code in zip(ciphertext, lcg_keystream(seed=seed)):
        byte_list.extend([byte ^ code])

    return bytes(byte_list)


from w1d1_test import test_decrypt


test_decrypt(lcg_decrypt)
from w1d1_test import test_stream_cipher


# test_stream_cipher(lcg_keystream, lcg_encrypt, lcg_decrypt)

# %%

"""
byte_list = []
    for byte, code in zip(plaintext, lcg_keystream(seed=seed)):
        byte_list.extend([byte ^ code ^ byte])
        code = byte ^ code ^ byte
        diff_byte ^ code ^ code
        byte_list2.extend([diff_byte ^ code])
"""


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

    def check_bytes(keystream_bytes: list[int], original_state: int) -> bool:
        state = original_state
        for kb in keystream_bytes[1:]:
            new_state = (a * state + c) % m
            if new_state & 0xFF != kb:
                return False
            state = new_state

        return True

    for i in range(0, 2**3):
        state_0 = i << 8 | keystream_bytes[0]
        if check_bytes(keystream_bytes, state_0):
            a_inv = pow(a, -1, m)
            seed = ((state_0 - c) * a_inv) % m
            return seed

    return -1


from w1d1_test import test_lcg_state_recovery


test_lcg_state_recovery(lcg_keystream, recover_lcg_state)
# %%

from w1d1_stream_cipher_secrets import intercept_messages

ciphertext1, ciphertext2 = intercept_messages(lcg_encrypt)
print(f"Intercepted ciphertext 1 ({len(ciphertext1)} bytes): {ciphertext1[:50].hex()}...")
print(f"Intercepted ciphertext 2 ({len(ciphertext2)} bytes): {ciphertext2[:50].hex()}...")

# %%

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

    m1_xor_m2 = []
    for c1, c2 in zip(ciphertext1, ciphertext2):
        m1_m2 = c1 ^ c2
        m1_xor_m2.append(m1_m2)

    guesses = []
    for i in range(0, len(m1_xor_m2) - len(crib)):
        guess = []
        for crib_char in crib:
            guess.append(m1_xor_m2[i] ^ crib_char)

        for b in guess:
            if b < 32 or b > 126:
                continue

        guesses.append((i, bytes(guess)))

    return guesses


from w1d1_test import test_crib_drag


correct_position = test_crib_drag(crib_drag, ciphertext1, ciphertext2)

## %


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


    TODO: Implement permutation
       - For each position i in the output
       - Get the source bit position from table[i]
       - Extract that bit from the input
       - Place it at position i in the output
    """
    out = 0x0

    for (rev_destination_index, source_index) in enumerate(table):
        places_to_shift_right = (in_width - 1) - source_index
        digit = (value >> places_to_shift_right) & 0x1
        places_to_shift_left = len(table) - rev_destination_index - 1
        shifted_digit = digit << places_to_shift_left
        out |= shifted_digit

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
    p10_permutation = permute_expand(key, p10, 10)

    left_half = (p10_permutation & 0x3e0) >> 5
    right_half = p10_permutation & 0x1F

    circular_left_half = left_half << 1 + ((left_half >> 4) & 0x1)
    circular_right_half = right_half << 1 + ((right_half >> 4) & 0x1)

    first_combined_halves = (circular_left_half << 5) + circular_right_half
    first_p8_permutation = permute_expand(first_combined_halves, p8, 10)

    more_circular_left_half = circular_left_half << 2 + ((circular_left_half >> 3) & 0x1)
    more_circular_right_half = circular_right_half << 2 + ((circular_right_half >> 3) & 0x1)

    second_combined_halves = (more_circular_left_half << 5) + more_circular_right_half

    second_p8_permutation = permute_expand(second_combined_halves, p8, 10)

    return first_p8_permutation, second_p8_permutation



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
    row = permute_expand(bits, [0, 3], 4)
    col = permute_expand(bits, [1, 2], 4)
    return sbox[row][col]



from w1d1_test import test_sbox_lookup


test_sbox_lookup(sbox_lookup, S0, S1)
# %%


def split_8_to_4s(input: int) -> tuple[int, int]:
    left_half = (input & 0b11110000) >> 4
    right_half = input & 0b00001111
    return left_half, right_half

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
    expanded_right_half = permute_expand(right, ep, 4)
    xored_with_subkey = expanded_right_half ^ subkey

    left_half, right_half = split_8_to_4s(xored_with_subkey)

    sbox_left = sbox_lookup(s0, left_half)
    sbox_right = sbox_lookup(s1, right_half)

    combined_sboxes = (sbox_left << 2) + sbox_right
    final_permutation = permute_expand(combined_sboxes, p4, 4)

    return final_permutation ^ left, right



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
    print(f"{ip=}")
    initial_permutation = permute_expand(byte, ip, 8)
    left, right = split_8_to_4s(initial_permutation)

    print(f"{format(initial_permutation, '08b')=}")
    print(f"{format(left, '04b')=}")
    print(f"{format(right, '04b')=}")

    left, right = fk(
        left,
        right,
        k1,
        ep,
        s0,
        s1,
        p4
    )

    left, right = right, left

    left, right = fk(
        left,
        right,
        k2,
        ep,
        s0,
        s1,
        p4
    )

    combined_fks = (left << 4) + right

    print(f"{format(combined_fks, '08b')=}")
    print(f"{format(left, '04b')=}")
    print(f"{format(right, '04b')=}")

    return permute_expand(combined_fks, ip_inv, 8)


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


from collections import defaultdict

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
    enc_table = defaultdict(list)
    for k_1_i in range(1024):
        enc_table[des_encrypt(k_1_i, plaintext)].append(k_1_i)

    working_pairs = set()
    for k_2_i in range(1024):
        dec = des_decrypt(k_2_i, ciphertext)
        if enc_table.get(dec, None) is not None:
            for k_1_i in enc_table[dec]:
                working_pairs.add((k_1_i, k_2_i))

    return sorted(list(working_pairs), key=lambda x : x[1])




    # TODO: Implement meet-in-the-middle attack
    #    - Build table of all encrypt(k1, plaintext)edes
    #    - For each k2, check if decrypt(k2, ciphertext) is in table
    #    - Return all matching (k1, k2) pairs
    pass

from w1d1_test import test_meet_in_the_middle


# Run the test
test_meet_in_the_middle(meet_in_the_middle_attack, double_encrypt)


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
    substitutions = []
    for i in range(4):
        nibble = (x >> (4 * i)) & 0b1111
        substitutions.append(sbox[nibble])

    combined = 0x0
    for substitution in reversed(substitutions):
        combined = ((combined << 4) + substitution)

    return combined



from w1d1_test import test_substitute


# Run the test
test_substitute(substitute, SBOX)


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
    return permute_expand(x, pbox, 16)

from w1d1_test import test_permute


# Run the test
test_permute(permute, PBOX)


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
    enc = block ^ keys[0]
    enc = substitute(enc, sbox)
    enc = permute(enc, pbox)
    enc = enc ^ keys[1]
    enc = substitute(enc, sbox)
    enc = permute(enc, pbox)
    return enc ^ keys[2]


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
    dec = block ^ keys[2]
    dec = permute(dec, inv_pbox)
    dec = substitute(dec, inv_sbox)
    dec = dec ^ keys[1]
    dec = permute(dec, inv_pbox)
    dec = substitute(dec, inv_sbox)
    return dec ^ keys[0]

from w1d1_test import test_block_cipher


# Run the test
test_block_cipher(encrypt_block, decrypt_block, round_keys, SBOX, PBOX, INV_SBOX, INV_PBOX)


def aes_encrypt(key: int, plaintext: bytes, sbox: List[int], pbox: List[int]) -> bytes:
    """
    Encrypt a message using ECB mode with our 16-bit block cipher.

    Process:
    1. Generate round keys from the main key
    2. Pad the message if necessary (with null bytes)
    3. Split into 2-byte blocks
    4. Encrypt each block
    5. Concatenate results (truncate padding if needed)

    Args:
        key: Encryption key (used as seed for round key generation)
        plaintext: Bytes to encrypt
        sbox: S-box for substitution
        pbox: P-box for permutation

    Returns:
        Encrypted bytes (same length as plaintext)
    """
    # TODO: Implement ECB encryption
    #    - Generate round keys using round_keys()
    #    - Handle padding if message length is odd
    #    - Process each 2-byte block
    #    - Return result truncated to original length
    keys = round_keys(key)

    plaintext_bytes = []
    for b in plaintext:
        plaintext_bytes.append(b)
    print(f"{plaintext_bytes=}")

    if len(plaintext) % 2 != 0:
        plaintext = plaintext + b'\0'

    result = bytearray()

    for i in range(len(plaintext) // 2):
        byte_one, byte_two = plaintext[i*2], plaintext[i*2+1]
        two_bytes = (byte_one << 8) + int(byte_two)
        encrypted = encrypt_block(two_bytes, keys, sbox, pbox)
        print(f"{format(encrypted, '016b')=}")
        enc_byte_one, enc_byte_two = (encrypted >> 8) & 0b11111111, encrypted & 0b11111111
        result.extend([enc_byte_one, enc_byte_two])

    return result


def aes_decrypt(key: int, ciphertext: bytes, inv_sbox: List[int], inv_pbox: List[int]) -> bytes:
    """
    Decrypt a message using ECB mode with our 16-bit block cipher.

    Process:
    1. Generate round keys from the main key
    2. Pad the ciphertext if necessary
    3. Split into 2-byte blocks
    4. Decrypt each block
    5. Concatenate results (truncate padding if needed)

    Args:
        key: Decryption key (same as encryption key)
        ciphertext: Bytes to decrypt
        inv_sbox: Inverse S-box for substitution
        inv_pbox: Inverse P-box for permutation

    Returns:
        Decrypted bytes (same length as ciphertext)
    """
    # TODO: Implement ECB decryption
    #    - Similar to encryption but use decrypt_block
    #    - Remember to use inverse S-box and P-box
    keys = round_keys(key)

    if len(ciphertext) % 2 == 1:
        ciphertext = ciphertext + b'\0'

    result = bytearray()
    for i in range(len(ciphertext) // 2):
        byte_one, byte_two = ciphertext[i*2], ciphertext[i*2+1]
        two_bytes = (byte_one << 8) + byte_two
        decrypted = decrypt_block(two_bytes, keys, inv_sbox, inv_pbox)
        result.extend([(decrypted >> 8) & 0b11111111, decrypted & 0b11111111])

    if result[-1] == 0:
        return result[:-1]
    else:
        return result


from w1d1_test import test_ecb_mode


# Run the test
test_ecb_mode(aes_encrypt, aes_decrypt, SBOX, PBOX, INV_SBOX, INV_PBOX)
