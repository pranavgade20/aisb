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
