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
