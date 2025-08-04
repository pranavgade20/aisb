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
          #  ^^^^^^ a

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
    left_half = (0b1111100000 | permuted) >> 5
    right_half = 0b0000011111 | permuted
    #    - Generate K1
    #       - Left shift both halves by 1 (LS-1)
    shifted_left_half = left_shift(left_half, 1, 5)
    shifted_right_half = left_shift(right_half, 1, 5)
    #       - Combine and apply P8
    combined = (shifted_left_half << 5) | shifted_right_half
    K1 = permute_expand(combined, p8, 8)
    #    - Generate K2
    #       - Left shift both halves by 2 (LS-2, for total LS-3)
    shifted_left_half = left_shift(shifted_left_half, 2, 5)
    shifted_right_half = left_shift(shifted_right_half, 2, 5)
    #       - Combine and apply P8
    combined = (shifted_left_half << 5) | shifted_right_half
    K2 = permute_expand(combined, p8, 8)
    #    - you might want to implement left_shift as a helper function
    #       - for example, left_shift 0b10101 by 1 gives 0b01011
    return(K1, K2)
from w1d1_test import test_key_schedule


# Run the test
test_key_schedule(key_schedule, P10, P8)

# %%
