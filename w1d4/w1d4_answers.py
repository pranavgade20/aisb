# %%


from typing import List
import math
from collections.abc import Callable
import hmac
import hashlib
import os
import sys
from typing import Tuple, Optional, Callable, Literal
import secrets
import json
from Crypto.Cipher import AES


sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
from aisb_utils import report


# %%


# MD5 uses four auxiliary functions that operate on three 32-bit words:
def md5_f(x: int, y: int, z: int) -> int:
    """MD5 auxiliary function F: (x & y) | (~x & z)"""
    return (x & y) | (~x & z)


def md5_g(x: int, y: int, z: int) -> int:
    """MD5 auxiliary function G: (x & z) | (y & ~z)"""
    return (x & z) | (y & ~z)


def md5_h(x: int, y: int, z: int) -> int:
    """MD5 auxiliary function H: x ^ y ^ z"""
    return x ^ y ^ z


def md5_i(x: int, y: int, z: int) -> int:
    """MD5 auxiliary function I: y ^ (x | ~z)"""
    return y ^ (x | ~z)


# Pre-computed sine-based constants using the formula T[i] = floor(2^32 * abs(sin(i+1)))
MD5_T = [int(math.floor((2**32) * abs(math.sin(i + 1)))) & 0xFFFFFFFF for i in range(64)]

# Rotation amounts for each round
MD5_S = [
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,
    7,
    12,
    17,
    22,  # Round 1
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,
    5,
    9,
    14,
    20,  # Round 2
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,
    4,
    11,
    16,
    23,  # Round 3
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,
    6,
    10,
    15,
    21,  # Round 4
]


# Helper functions for converting between bytes and integers.
# These functions are provided for you to save time on code less relevant to the goals of the exercise;
# But you can re-implement them yourself if you want to practice bit manipulation!
def bytes_to_int32_le(data: bytes, offset: int) -> int:
    """Convert 4 bytes starting at offset to 32-bit little-endian integer."""
    return data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24)


def int32_to_bytes_le(value: int) -> bytes:
    """Convert 32-bit integer to 4 bytes in little-endian format."""
    return bytes([value & 0xFF, (value >> 8) & 0xFF, (value >> 16) & 0xFF, (value >> 24) & 0xFF])


def int64_to_bytes_le(value: int) -> bytes:
    """Convert 64-bit integer to 8 bytes in little-endian format."""
    low_32 = value & 0xFFFFFFFF
    high_32 = (value >> 32) & 0xFFFFFFFF
    return int32_to_bytes_le(low_32) + int32_to_bytes_le(high_32)


def left_rotate(value: int, amount: int) -> int:
    """Left rotate a 32-bit integer by the specified amount."""
    # Ensure we're working with 32-bit values
    value &= 0xFFFFFFFF
    return ((value << amount) | (value >> (32 - amount))) & 0xFFFFFFFF


# === Start implementing from here ===
def md5_padding(message: bytes) -> bytes:
    """
    Apply MD5 padding to message.

    MD5 padding works as follows:
    1. Append a single '1' bit (together with trailing zeroes, corresponds to a 0x80 byte)
    2. Append '0' bits until message length ≡ 448 bits mod 512 (i.e., 56 bytes mod 64)
    3. Append original message length as 64-bit little-endian integer

    Args:
        message: Input message as bytes

    Returns:
        Padded message ready for MD5 processing.
        The result has length in bytes divisible by 64 and the last 8 bytes are the length of the original message.
    """
    # TODO: Implement MD5 padding
    # 1. Save original message length in bytes
    # 2. Append 0x80 (the '1' bit)
    # 3. Pad with zero bytes until the size modulo 64 is 56
    # 4. Convert message length to bits
    # 5. Append bit-length as 64-bit little-endian
    length = len(message) * 8
    message = message + bytes([0x80])

    while len(message) % 64 != 56:
        message = message + bytes([0])

    message = message + int64_to_bytes_le(length)

    return message


from w1d4_test import test_left_rotate
from w1d4_test import test_md5_padding_length
from w1d4_test import test_md5_padding_content


test_left_rotate(left_rotate)
test_md5_padding_length(md5_padding)
test_md5_padding_content(md5_padding)

# %%


def md5_process_block(block: bytes, state: List[int]) -> List[int]:
    """
    Process a single 512-bit block with MD5 algorithm.

    Args:
        block: 64-byte block to process
        state: Current MD5 state: variables [A, B, C, D]

    Returns:
        Updated MD5 state
    """
    assert len(state) == 4, "State must be a list of 4 32-bit integers"

    # 1. Convert 64-byte block into 16 32-bit words in little-endian order
    #    - use the bytes_to_int32_le function
    X = bytes_to_int32_le(block, 0)

    # 2. Initialize A, B, C, D from state
    A, B, C, D = state

    # 3. For each of 64 rounds (i from 0 to 63)
    for i in range(64):
        # Choose function and k
        if i < 16:
            # * Round 1 (i < 16): use md5_f, k = i
            fun = md5_f
            k = i
        elif i < 32:
            # * Round 2 (i < 32): use md5_g, k = (5*i + 1) % 16
            fun = md5_g
            k = (5 * i + 1) % 16
        elif i < 48:
            # * Round 3 (i < 48): use md5_h, k = (3*i + 5) % 16
            fun = md5_h
            k = (3 * i + 5) % 16
        else:
            #  * Round 4 (i >= 48): use md5_i, k = (7*i) % 16
            fun = md5_i
            k = (7 * i) % 16
        # Compute temp = A + function(B,C,D) + X[k] + MD5_T[i]
        temp = A + fun(B, C, D) + X[k] + MD5_T[i]
        # Mask the value to the low 32 bits
        temp = temp & (2**32 - 1)
        # Left rotate the value by MD5_S[i] bits (use the left_rotate function)
        temp = left_rotate(temp, MD5_S[i])
        # Add B to the rotated value
        temp += B
        # Mask the result temp value to the low 32 bits
        temp = temp & (2**32 - 1)
        # Rotate the state variables: A,B,C,D = D,temp,B,C
        A, B, C, D = D, temp, B, C

    # 4. Return the new state:
    # add the resulting values of A, B, C, D to the respective values in the state given in the argument
    # mask the new state values to the low 32 bits
    state[0] = (state[0] + A) & (2**32 - 1)
    state[1] = (state[1] + B) & (2**32 - 1)
    state[2] = (state[2] + C) & (2**32 - 1)
    state[3] = (state[3] + D) & (2**32 - 1)

    # return new state
    return state


def md5_hash(message: bytes) -> bytes:
    """
    Compute MD5 hash of message.

    Args:
        message: Input message as bytes

    Returns:
        16-byte MD5 hash
    """
    # TODO: Implement MD5 hash function
    # 1. Initialize state with MD5 magic constants: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    # 2. Pad the message using md5_padding() to make the length in bytes divisible by 64
    # 3. Process each 64-byte block:
    #    - For each block, apply the md5_process_block function to the block and the current state
    #    - Update the current state to be the result of md5_process_block
    # 4. Convert final state to bytes:
    #    - convert the state values to little-endian bytes
    #    - concatenate the bytes to get the final hash bytes

    pass


def md5_hex(message: bytes) -> str:
    """Compute MD5 hash and return as hex string."""
    return md5_hash(message).hex()


from w1d4_test import test_md5_process_block
from w1d4_test import test_md5


test_md5_process_block(md5_process_block)
test_md5(md5_hex)
