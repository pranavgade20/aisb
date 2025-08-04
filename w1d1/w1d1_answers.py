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
    initial_list = [int(i) for i in format(value, 'b')]
    final_list = []
    for p_index in table:
        final_list.append(initial_list[p_index])
    return int(''.join([str(i) for i in final_list]), 2)


from w1d1_test import test_permute_expand


# Run the test
test_permute_expand(permute_expand)
