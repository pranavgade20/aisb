# %%

import os
import sys
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




111111111111111111111110000010
----------------------11111111
----------------------10000010
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
    byte_value = value.to_bytes(in_width)
    
    # print(value)
    # print(table)
    # print(in_width)

    out = [0]*in_width

    for i in range(in_width):
        # out.append(byte_value[table[i]])
        index = table[i]
        bit = (value >> index) & 1
        out[i] = (out[i] | bit)

    out = out[::-1]
    res = 0
    for bit in out:
        res = (res << 1) | bit

    print(bin(res))
    return bin(res)

from w1d1_test import test_permute_expand

# Run the test
test_permute_expand(permute_expand)

# %%
