# %%

import os
import sys
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
    x = seed
    a = 1664525
    c = 1013904223
    m = 2**32

    while True:
        x = (a * x + c) % m
        yield x & (2**8 - 1)


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
    encrypted_bytes = []
    for c, n in zip(plaintext, lcg_keystream(seed)):
        encrypted_bytes.append(c ^ n)
    return bytes(encrypted_bytes)


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

    # TODO: Implement LCG state recovery
    #   - brute-force through all possible upper 24 bits - this will let you try all possible starting states
    #   - for each state, check if it produces the correct bytes
    #   - if it does, calculate the seed by rearranging the LCG formula to get a formula for the seed

    b0 = keystream_bytes[0]

    for upper_bits in range(2**24):
        state_0 = (upper_bits << 8) | b0
        state = state_0

        valid = True

        for i in range(1, len(keystream_bytes)):
            state = (a * state + c) % m
            if (state & 0xFF) != keystream_bytes[i]:
                valid = False
                break

        if valid:
            a_inv = pow(a, -1, m)
            seed = ((state_0 - c) * a_inv) % m
            return seed


from w1d1_test import test_lcg_state_recovery

test_lcg_state_recovery(lcg_keystream, recover_lcg_state)
# %%


from w1d1_stream_cipher_secrets import intercept_messages

ciphertext1, ciphertext2 = intercept_messages(lcg_encrypt)
print(f"Intercepted ciphertext 1 ({len(ciphertext1)} bytes): {ciphertext1[:50].hex()}...")
print(f"Intercepted ciphertext 2 ({len(ciphertext2)} bytes): {ciphertext2[:50].hex()}...")


# %%
def byte_xor(byte1: bytes, byte2: bytes):
    return bytes(a ^ b for a, b in zip(byte1, byte2))


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
    xor_c = byte_xor(ciphertext1, ciphertext2)
    delta = len(crib)
    output = []

    for i in range(len(xor_c) - delta):
        slice = xor_c[i : i + delta]
        xor_slice = byte_xor(slice, crib)
        if all(32 <= c <= 126 for c in xor_slice):
            output.append((i, xor_slice))
    return output


from w1d1_test import test_crib_drag


correct_position = test_crib_drag(crib_drag, ciphertext1, ciphertext2)

# %%


def recover_seed(ciphertext: bytes, known_plaintext: bytes, position: int) -> int:
    """
    Recover the original LCG seed from a known plaintext fragment at a specific position.

    This function recovers keystream bytes at the given position, finds the LCG state
    that produced them, then reverses the LCG to find the original seed.

    Args:
        ciphertext: The ciphertext containing the known plaintext
        known_plaintext: The known plaintext fragment
        position: The position where known_plaintext appears in the original message

    Returns:
        The original seed used to encrypt the message
    """
    a = 1664525
    c = 1013904223
    m = 2**32
    # TODO: Implement seed recovery
    #   - Use the known plaintext to recover keystream bytes at the given position
    #   - Call recover_lcg_state(keystream_bytes) to get the seed that produces these bytes
    #   - note that the seed at this position is the same as the state - so you can reverse the LCG 'position' times to get back to the original seed
    #
    # Hints:
    # 1. Recover keystream bytes at position:
    #    keystream[i] = ciphertext[position+i] XOR known_plaintext[i]
    # 2. Call recover_lcg_state(keystream) to get the seed that produces these bytes
    # 3. Reverse the LCG 'position' times to get back to the original seed:
    #    - a_inv = pow(a, -1, m)
    #    - state = ((state - c) * a_inv) % m
    # 4. Return the original seed

    keystream = []

    for i in range(len(known_plaintext) - position):
        keystream.append(ciphertext[position + i] ^ known_plaintext[i])

    keystream = bytes(keystream)

    state = recover_lcg_state(keystream)

    for i in range(position):
        a_inv = pow(a, -1, m)
        state = ((state - c) * a_inv) % m

    return state


from w1d1_test import test_recover_seed


test_recover_seed(recover_seed, lcg_decrypt, ciphertext1, correct_position)

# %%


def recover_messages(
    ciphertext1: bytes, ciphertext2: bytes, known_plaintext: bytes, position: int
) -> tuple[bytes, bytes]:
    """
    Recover both messages using a known plaintext fragment.

    Args:
        ciphertext1: First ciphertext (contains known_plaintext)
        ciphertext2: Second ciphertext
        known_plaintext: Known fragment from message1
        position: Position of known_plaintext in message1

    Returns:
        Tuple of (recovered_message1, recovered_message2)
    """
    # TODO: Implement message recovery using recover_seed
    #   - Call recover_seed to get the original seed
    #   - Use decrypt to get both messages
    #
    # Hints:
    # 1. Call recover_seed(ciphertext1, known_plaintext, position) to get the original seed
    # 2. Use decrypt(seed, ciphertext1) and decrypt(seed, ciphertext2) to decrypt both messages
    # 3. Verify that known_plaintext appears in msg1 at the expected position:
    #    msg1[position:position+len(known_plaintext)] == known_plaintext
    # 4. Return (msg1, msg2) if successful, or (b"", b"") if verification fails

    # positions = crib_drag(ciphertext1, ciphertext2, known_plaintext)

    seed = recover_seed(ciphertext1, known_plaintext, position)
    msg1 = lcg_decrypt(seed, ciphertext1)
    msg2 = lcg_decrypt(seed, ciphertext2)

    if msg1[position : position + len(known_plaintext)] == known_plaintext:
        return msg1, msg2

    return b"", b""


# Perform the full attack
print("\nPerforming full message recovery...")
recovered_msg1, recovered_msg2 = recover_messages(
    ciphertext1, ciphertext2, b"linear congruential generator", correct_position
)

if recovered_msg1 and recovered_msg2:
    print("\n" + "=" * 60)
    print("RECOVERED MESSAGES:")
    print("\nMessage 1:")
    print(recovered_msg1.decode())
    print("\nMessage 2:")
    print(recovered_msg2.decode())
    print("\n" + "=" * 60)
else:
    print("\nMessage recovery failed!")


# %%
def permute_expand(value: int, table: list[int], in_width: int) -> int:
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
    permuted_key = permute_expand(key, p10, 10)
    left = permuted_key >> 5
    right = permuted_key - (left << 5)

    left = permute_expand(left, [1, 2, 3, 4, 0], 5)
    right = permute_expand(right, [1, 2, 3, 4, 0], 5)

    K1 = (left << 5) | right
    K1 = permute_expand(K1, p8, 10)

    left = permute_expand(left, [2, 3, 4, 0, 1], 5)
    right = permute_expand(right, [2, 3, 4, 0, 1], 5)

    K2 = (left << 5) | right
    K2 = permute_expand(K2, p8, 10)

    return K1, K2


from w1d1_test import test_key_schedule


# Run the test
test_key_schedule(key_schedule, P10, P8)


# %%
def bit2int(bits: list[int]):
    output = 0
    for bit in bits:
        output = output << 1
        output += bit
    return output


def int2bitlist(input: int, size: int):
    temp = list(map(int, bin(input)[2:]))
    return [0] * (size - len(temp)) + temp


def sbox_lookup(sbox: list[list[int]], bits: int) -> int:
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
    bitlist = int2bitlist(bits, 4)
    row = bit2int([bitlist[0], bitlist[3]])
    col = bit2int([bitlist[1], bitlist[2]])

    return sbox[row][col]


from w1d1_test import test_sbox_lookup


test_sbox_lookup(sbox_lookup, S0, S1)


# %%
def fk(
    left: int, right: int, subkey: int, ep: list[int], s0: list[list[int]], s1: list[list[int]], p4: list[int]
) -> tuple[int, int]:
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
    exp_right = permute_expand(right, ep, 4)
    xor_exp_right = exp_right ^ subkey
    l = xor_exp_right >> 4
    r = xor_exp_right - (l << 4)

    sbox_left = sbox_lookup(s0, l)
    sbox_right = sbox_lookup(s1, r)

    combined_sbox = (sbox_left << 4) + sbox_right
    p4_combined_sbox = permute_expand(combined_sbox, p4, 8)

    new_left = left ^ p4_combined_sbox

    return (new_left, right)


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
    # 1
    x = byte
    x = permute_expand(x, ip, 8)

    # 2
    l = x >> 4
    r = x - (l << 4)

    # 3
    l, r = fk(l, r, k1, ep, s0, s1, p4)

    # 4
    l, r = r, l

    # 5
    l, r = fk(l, r, k2, ep, s0, s1, p4)

    # 6
    x = (l << 4) | r
    x = permute_expand(x, ip_inv, 8)

    return x


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
