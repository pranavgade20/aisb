# %%
"""
Authors: Meeri and Chris
"""

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


# %%
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

    # bytes?

    message2 = message + b"\x80"
    message2_length = len(message2)

    current_remainder = message2_length % 64
    if current_remainder <= 56:
        number_of_zero_bytes = 56 - current_remainder
    else:
        number_of_zero_bytes = 64 + 56 - current_remainder

    message3 = message2 + b"\x00" * number_of_zero_bytes

    message4_length = int64_to_bytes_le(len(message) * 8)

    return message3 + message4_length


from w1d4_test import test_left_rotate
from w1d4_test import test_md5_padding_length
from w1d4_test import test_md5_padding_content

test_left_rotate(left_rotate)
test_md5_padding_length(md5_padding)
test_md5_padding_content(md5_padding)

# %%
bin(0x80)
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

    # TODO: Implement MD5 block processing
    # 1. Convert 64-byte block into 16 32-bit words in little-endian order
    #    - use the bytes_to_int32_le function

    words = []
    for i in range(16):
        offset = i * 32 // 8
        word = bytes_to_int32_le(block, offset)
        words.append(word)

    A, B, C, D = state

    for i in range(64):
        if i < 16:
            fun = md5_f
            k = i
        elif i < 32:
            fun = md5_g
            k = (5 * i + 1) % 16
        elif i < 48:
            fun = md5_h
            k = (3 * i + 5) % 16
        elif i >= 48:
            fun = md5_i
            k = (7 * i) % 16

        temp = A + fun(B, C, D) + words[k] + MD5_T[i]
        masked = temp & 0xFFFFFFFF

        rotated = left_rotate(masked, MD5_S[i])
        rotated_plus_B = rotated + B

        rotated_masked = rotated_plus_B & 0xFFFFFFFF

        A, B, C, D = D, rotated_masked, B, C

    # 3. For each of 64 rounds (i from 0 to 63):
    #    - Choose function and message index k based on round:
    #      * Round 1 (i < 16): use md5_f, k = i
    #      * Round 2 (i < 32): use md5_g, k = (5*i + 1) % 16
    #      * Round 3 (i < 48): use md5_h, k = (3*i + 5) % 16
    #      * Round 4 (i >= 48): use md5_i, k = (7*i) % 16
    #    - Compute value: temp = A + function(B,C,D) + X[k] + MD5_T[i]
    #    - Mask the value to the low 32 bits
    #    - Left rotate the value by MD5_S[i] bits (use the left_rotate function)
    #    - Add B to the rotated value
    #    - Mask the result temp value to the low 32 bits

    #    - Rotate the state variables: A,B,C,D = D,temp,B,C
    # 4. Return the new state:
    state[0] = (state[0] + A) & 0xFFFFFFFF
    state[1] = (state[1] + B) & 0xFFFFFFFF
    state[2] = (state[2] + C) & 0xFFFFFFFF
    state[3] = (state[3] + D) & 0xFFFFFFFF
    #    - add the resulting values of A, B, C, D to the respective values in the state given in the argument
    #    - e.g., state[0] = (state[0] + A)
    #    - mask the new state values to the low 32 bits
    return state


from w1d4_test import test_md5_process_block

test_md5_process_block(md5_process_block)
# %%


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
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    # 2. Pad the message using md5_padding() to make the length in bytes divisible by 64
    message = md5_padding(message)

    # 3. Process each 64-byte block:
    #    - For each block, apply the md5_process_block function to the block and the current state
    length = len(message)
    blocknumber = length // 64  # len is divisible by 64
    # slicing
    blocklist = []
    for i in range(blocknumber):
        block = message[i * 64 : (i + 1) * 64]
        blocklist.append(block)
        state = md5_process_block(block, state)

    #    - Update the current state to be the result of md5_process_block
    # 4. Convert final state to bytes:

    #    - convert the state values to little-endian bytes
    hashbytes = b""
    for statevalue in state:
        statevalue = int32_to_bytes_le(statevalue)
        #    - concatenate the bytes to get the final hash bytes
        hashbytes = hashbytes + statevalue
    return hashbytes


def md5_hex(message: bytes) -> str:
    """Compute MD5 hash and return as hex string."""
    return md5_hash(message).hex()


from w1d4_test import test_md5_process_block
from w1d4_test import test_md5


test_md5_process_block(md5_process_block)
test_md5(md5_hex)


# Famous MD5 collision pair discovered by researchers
COLLISION_A = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70"
)

COLLISION_B = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70"
)


def demonstrate_md5_collision():
    """Show that two different messages can have the same MD5 hash."""
    print("\nMessage differences at positions:")
    for i, (a, b) in enumerate(zip(COLLISION_A, COLLISION_B)):
        if a != b:
            print(f"  Position {i}: {a:02x} vs {b:02x}")

    hash_a = md5_hex(COLLISION_A)
    hash_b = md5_hex(COLLISION_B)

    print("MD5 Collision Demonstration")
    print("=" * 40)
    print(f"Message A: {COLLISION_A.hex()[:60]}...")
    print(f"MD5(A):    {hash_a}")
    print()
    print(f"Message B: {COLLISION_B.hex()[:60]}...")
    print(f"MD5(B):    {hash_b}")
    print()
    print(f"Messages identical? {COLLISION_A == COLLISION_B}")
    print(f"Hashes identical? {hash_a == hash_b}")


demonstrate_md5_collision()


def naive_mac(message: bytes, secret: bytes) -> bytes:
    """
    Naive message authentication: Hash(secret || message)

    Args:
        message: The message to authenticate
        secret: Secret key known only to legitimate parties
    Returns:
        Authentication tag
    """
    # TODO: Implement naive MAC
    # Concatenate secret and message, then hash the result
    # Use the md5_hash function you implemented earlier

    return md5_hash(secret + message)


def naive_verify(message: bytes, secret: bytes, tag: bytes) -> bool:
    """
    Verify a message using the naive MAC.

    Args:
        message: The message to verify
        secret: Secret key
        tag: Authentication tag to check

    Returns:
        True if the tag is valid for the message
    """
    # TODO: Implement naive verification
    # Compute the expected tag for the message and compare it with the provided tag
    return naive_mac(message, secret) == tag


from w1d4_test import test_naive_mac


test_naive_mac(naive_mac, naive_verify)


# %%
def calculate_glue(msg):
    new_message = md5_padding(msg)
    return new_message[len(msg) :]


def length_extension_attack(
    original_message: bytes,
    original_tag: bytes,
    secret_length: int,
    additional_data: bytes,
) -> tuple[bytes, bytes]:
    """
    Perform a length extension attack against the naive MAC.

    This demonstrates how an attacker can forge valid MACs for new messages
    without knowing the secret key.

    Args:
        original_message: Message with known valid MAC
        original_tag: Valid MAC for original_message
        secret_length: Length of the secret (often can be guessed/brute-forced)
        additional_data: Data to append and authenticate

    Returns:
        (forged_message, forged_tag) - New message and its valid MAC
    """

    # Step 5: Continue MD5 processing from the known state
    # - Process (additional_data + final_padding) starting from the extracted state
    # - Use md5_process_block for each 64-byte block

    # Step 6: Convert final state back to bytes for the forged tag

    # Step 1: Determine the "glue padding" that MD5 applied to (secret || original_message)
    # - The padding only depends on input length, not contents,
    #   therefore you can use a dummy value of secret_length + len(original_message) to construct input to md5_padding(),
    # - Extract just the padding part that was added as glue_padding

    glue_padding = calculate_glue(b"\x00" * (secret_length + len(original_message)))

    # Step 2: Build the forged message that the attacker will present as
    #   concatenation of original_message + glue_padding + additional_data
    forgedmessage = original_message + glue_padding + additional_data

    # Step 3: Convert the original tag back to MD5 internal state
    # - The tag represents the MD5 state after processing (secret || original_message || glue_padding)
    # - Use bytes_to_int32_le to extract 4 32-bit words from the tag
    state = []
    for i in range(4):
        state.append(bytes_to_int32_le(original_tag, 4 * i))

    # Step 4: Determine what final padding is needed
    # - Calculate total length: secret_length + len(original_message) + len(glue_padding) + len(additional_data)
    # - Create dummy data of that length and apply md5_padding()
    # - Extract the final padding that would be added
    totallen = secret_length + len(original_message) + len(glue_padding) + len(additional_data)
    dummy = b"\x00" * totallen
    dummy2 = md5_padding(dummy)
    pad = dummy2[len(dummy) :]

    # Step 5: Continue MD5 processing from the known state
    # - Process (additional_data + final_padding) starting from the extracted state
    # - Use md5_process_block for each 64-byte block
    # 3. Process each 64-byte block:
    #    - For each block, apply the md5_process_block function to the block and the current state
    message = additional_data + pad
    length = len(message)
    blocknumber = length // 64  # len is divisible by 64
    # slicing
    blocklist = []
    for i in range(blocknumber):
        block = message[i * 64 : (i + 1) * 64]
        blocklist.append(block)
        state = md5_process_block(block, state)

    #    - Update the current state to be the result of md5_process_block
    # 4. Convert final state to bytes:

    #    - convert the state values to little-endian bytes
    hashbytes = b""
    for statevalue in state:
        statevalue = int32_to_bytes_le(statevalue)
        #    - concatenate the bytes to get the final hash bytes
        hashbytes = hashbytes + statevalue
    return forgedmessage, hashbytes


from w1d4_test import test_length_extension_attack


test_length_extension_attack(length_extension_attack, naive_mac, naive_verify)


import random
from typing import List


def _is_probable_prime(n: int, rounds: int = 5) -> bool:
    """Return True if ``n`` passes a Miller-Rabin primality test."""
    if n in (2, 3):
        return True
    if n <= 1 or n % 2 == 0:
        return False

    # Write n-1 as d * 2^s
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def get_prime(bits: int, rng: random.Random | None = None) -> int:
    if rng is None:
        rng = random.Random()

    while True:
        candidate = rng.getrandbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate
