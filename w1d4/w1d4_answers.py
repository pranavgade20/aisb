# %%
import hashlib
import hmac
import json
import math
import os
import secrets
import sys
from collections.abc import Callable
from re import I
from typing import Callable, List, Literal, Optional, Tuple

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
    # TODO: Implement MD5 padding
    # 1. Save original message length in bytes
    message_len = len(message)
    # 2. Append 0x80 (the '1' bit)
    rounded_message = message + b"\x80"
    # 3. Pad with zero bytes until the size modulo 64 is 56
    cur_size = (message_len + 1) % 64
    if cur_size <= 56:
        padding = b"\x00" * (56 - cur_size)
    else:
        padding = b"\x00" * (64 - cur_size + 56)

    padded_message = rounded_message + padding

    # assert len(rounded_message) % 64 == 56
    # 4. Convert message length to bits
    len_in_bits = message_len * 8
    # 5. Append bit-length as 64-bit little-endian
    padded_message += int64_to_bytes_le(len_in_bits)
    return padded_message


from w1d4_test import test_left_rotate, test_md5_padding_content, test_md5_padding_length

test_left_rotate(left_rotate)
test_md5_padding_length(md5_padding)
test_md5_padding_content(md5_padding)

# %%


# def md5_process_block(block: bytes, state: List[int]) -> List[int]:
#     """
#     Process a single 512-bit block with MD5 algorithm.

#     Args:
#         block: 64-byte block to process
#         state: Current MD5 state: variables [A, B, C, D]

#     Returns:
#         Updated MD5 state
#     """
#     assert len(state) == 4, "State must be a list of 4 32-bit integers"
#     # TODO: Implement MD5 block processing
#     # 1. Convert 64-byte block into 16 32-bit words in little-endian order
#     #    - use the bytes_to_int32_le function
#     X = [bytes_to_int32_le(block, offset) for offset in range(0, 64, 4)]
#     # 2. Initialize A, B, C, D from state
#     assert len(state) == 4
#     A, B, C, D = state

#     # 3. For each of 64 rounds (i from 0 to 63):

#     #    - Choose function and message index k based on round:
#     #      * Round 1 (i < 16): use md5_f, k = i
#     #      * Round 2 (i < 32): use md5_g, k = (5*i + 1) % 16
#     #      * Round 3 (i < 48): use md5_h, k = (3*i + 5) % 16
#     #      * Round 4 (i >= 48): use md5_i, k = (7*i) % 16
#     def get_round(i: int) -> Tuple[Callable[...], int]:
#         if i < 16:
#             return md5_f, i
#         elif 16 <= i < 32:
#             return md5_g, (5 * i + 1) % 16
#         elif 32 <= i < 48:
#             return md5_h, (3 * i + 5) % 16
#         elif i >= 48:
#             return md5_i, (7 * i) % 16

#     #    - Compute value: temp = A + function(B,C,D) + X[k] + MD5_T[i]
#     for i in range(64):
#         function, k = get_round(i)
#         temp = A + function(B, C, D) + X[k] + MD5_T[i]
#         #    - Mask the value to the low 32 bits
#         temp_masked = temp & 0xFFFFFFFF
#         #    - Left rotate the value by MD5_S[i] bits (use the left_rotate function)
#         rotated = left_rotate(temp_masked, MD5_S[i])
#         #    - Add B to the rotated value
#         b_added = B + rotated
#         #    - Mask the result temp value to the low 32 bits
#         b_added_masked = b_added & 0xFFFFFFFF
#         #    - Rotate the state variables: A,B,C,D = D,temp,B,C
#         A, B, C, D = D, b_added_masked, B, C
#         # 4. Return the new state:
#         #    - add the resulting values of A, B, C, D to the respective values in the state given in the argument
#         #    - e.g., state[0] = (state[0] + A)
#         assert len(state) == 4

#     state[0] = (state[0] + A) & 0xFFFFFFFF
#     state[1] = (state[1] + B) & 0xFFFFFFFF
#     state[2] = (state[2] + C) & 0xFFFFFFFF
#     state[3] = (state[3] + D) & 0xFFFFFFFF
#     #    - mask the new state values to the low 32 bits

#     return state


# def md5_hash(message: bytes) -> bytes:
#     """
#     Compute MD5 hash of message.

#     Args:
#         message: Input message as bytes

#     Returns:
#         16-byte MD5 hash
#     """
#     # TODO: Implement MD5 hash function
#     # 1. Initialize state with MD5 magic constants: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
#     state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
#     # 2. Pad the message using md5_padding() to make the length in bytes divisible by 64
#     padded_message = md5_padding(message)
#     # 3. Process each 64-byte block:
#     blocks: list[bytes] = []
#     i = 0
#     while i + 64 < len(padded_message):
#         block = padded_message[i : i + 64]
#         blocks.append(block)
#         i += 64
#     assert len(blocks) == len(padded_message) / 64

#     #    - For each block, apply the md5_process_block function to the block and the current state
#     for block in blocks:
#         #    - Update the current state to be the result of md5_process_block
#         state = md5_process_block(block, state)
#     # 4. Convert final state to bytes:
#     #    - convert the state values to little-endian bytes

#     #    - concatenate the bytes to get the final hash bytes
#     result = b""
#     for word in state:
#         result += int32_to_bytes_le(word)
#     return result
#     pass


# def md5_hex(message: bytes) -> str:
#     """Compute MD5 hash and return as hex string."""
#     return md5_hash(message).hex()


# from w1d4_test import test_md5, test_md5_process_block

# test_md5_process_block(md5_process_block)
# test_md5(md5_hex)


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
    # Convert 64-byte block to 16 32-bit little-endian words
    X = []
    for i in range(16):
        word = bytes_to_int32_le(block, i * 4)
        X.append(word)

    # Initialize working variables
    A, B, C, D = state

    # Process 64 rounds
    for i in range(64):
        if i < 16:
            # Round 1: F function
            f_result = md5_f(B, C, D)
            k = i
        elif i < 32:
            # Round 2: G function
            f_result = md5_g(B, C, D)
            k = (5 * i + 1) % 16
        elif i < 48:
            # Round 3: H function
            f_result = md5_h(B, C, D)
            k = (3 * i + 5) % 16
        else:
            # Round 4: I function
            f_result = md5_i(B, C, D)
            k = (7 * i) % 16

        # MD5 round operation
        temp = (A + f_result + X[k] + MD5_T[i]) & 0xFFFFFFFF
        temp = left_rotate(temp, MD5_S[i])
        temp = (B + temp) & 0xFFFFFFFF

        # Rotate variables: A, B, C, D = D, temp, B, C
        A, B, C, D = D, temp, B, C

    # Add this block's hash to the state
    state[0] = (state[0] + A) & 0xFFFFFFFF
    state[1] = (state[1] + B) & 0xFFFFFFFF
    state[2] = (state[2] + C) & 0xFFFFFFFF
    state[3] = (state[3] + D) & 0xFFFFFFFF

    return state


def md5_hash(message: bytes) -> bytes:
    """
    Compute MD5 hash of message.

    Args:
        message: Input message as bytes

    Returns:
        16-byte MD5 hash
    """
    # MD5 initial state (magic constants)
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    # Apply padding
    padded_msg = md5_padding(message)

    # Process each 512-bit block
    for i in range(0, len(padded_msg), 64):
        block = padded_msg[i : i + 64]
        state = md5_process_block(block, state)

    # Convert state to bytes (little-endian)
    result = b""
    for word in state:
        result += int32_to_bytes_le(word)
    return result


def md5_hex(message: bytes) -> str:
    """Compute MD5 hash and return as hex string."""
    return md5_hash(message).hex()


from w1d4_test import test_md5, test_md5_process_block

test_md5_process_block(md5_process_block)
test_md5(md5_hex)


# %%
def hmac_md5(key: bytes, message: bytes) -> bytes:
    """
    Implement HMAC using MD5 as the underlying hash function.

    Args:
        key: Secret key for authentication
        message: Message to authenticate

    Returns:
        HMAC tag (16 bytes for MD5)
    """
    block_size = 64  # MD5 block size in bytes - normalize the key length to this size
    ipad = 0x36  # Inner padding byte
    opad = 0x5C  # Outer padding byte
    # TODO: Implement HMAC-MD5

    # Step 1: Normalize the key length
    # - If key longer than block_size, hash it with md5_hash
    if len(key) > block_size:
        key = md5_hash(key)
    # - Otherwise, pad key to exactly block_size bytes with null bytes
    else:
        while len(key) < 64:
            key += b"\x00"

    # Step 2: Compute inner hash
    # - compute Hash(ipad ⊕ key || message)
    # Hint: Use bytes(k ^ ipad for k in key) for XOR operation
    ipad_key = bytes(k ^ ipad for k in key)
    ihash = md5_hash(ipad_key + message)

    # Step 3: Compute HMAC
    # - compute Hash(opad ⊕ key || inner_hash)
    opad_key = bytes(k ^ opad for k in key)
    ohash = md5_hash(opad_key + ihash)

    return ohash


def hmac_verify(key: bytes, message: bytes, tag: bytes) -> bool:
    """
    Verify an HMAC tag.

    Args:
        key: Secret key
        message: Message to verify
        tag: HMAC tag to check

    Returns:
        True if tag is valid
    """
    expected_tag = hmac_md5(key, message)
    return expected_tag == tag


from w1d4_test import test_hmac_md5, test_hmac_verify

test_hmac_md5(hmac_md5)
test_hmac_verify(hmac_verify)

# %%


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


# %%


def generate_keys(bits: int = 16) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """Generate RSA public and private keys.

    Steps:
    1. Generate two primes p and q of bits//2 length each
    2. Ensure p ≠ q
    3. Compute n = p × q and φ(n) = (p-1) × (q-1)
    4. Choose e (try 65537 first, fall back if needed)
    5. Compute d = e⁻¹ mod φ(n)

    Args:
        bits: Approximate bit length of the modulus n.

    Returns:
        ((n, e), (n, d)) - public and private key tuples
    """
    while True:
        p = get_prime(bits // 2)
        q = get_prime(bits // 2)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        if math.gcd(phi, e) <= 1:
            d = pow(e, -1, phi)
            return ((n, e), (n, d))


from w1d4_test import test_generate_keys

test_generate_keys(generate_keys)

# %%


def encrypt_rsa(public_key: Tuple[int, int], message: str) -> List[int]:
    """Encrypt a UTF-8 string one byte at a time.

    Process each byte of the message:
    1. Convert message to UTF-8 bytes
    2. For each byte b, compute c = b^e mod n
    3. Return list of encrypted values

    Args:
        public_key: Tuple (n, e) of modulus and public exponent
        message: The plaintext string

    Returns:
        List of encrypted integers (one per byte)
    """
    # TODO: Implement encryption
    #    - Extract n and e from public_key
    n, e = public_key
    #    - Convert message to bytes with .encode("utf-8")
    msg_bytes = message.encode("utf-8")
    #    - Encrypt each byte with pow(byte, e, n)
    return [pow(byte, e, n) for byte in msg_bytes]


def decrypt_rsa(private_key: Tuple[int, int], ciphertext: List[int]) -> str:
    """Decrypt a list of integers with the private key.

    Process each encrypted value:
    1. For each ciphertext c, compute m = c^d mod n
    2. Collect decrypted values as bytes
    3. Decode UTF-8 string

    Args:
        private_key: Tuple (n, d) of modulus and private exponent
        ciphertext: List of encrypted integers

    Returns:
        Decrypted string
    """
    # TODO: Implement decryption
    #    - Extract n and d from private_key
    n, d = private_key
    #    - Decrypt each value with pow(c, d, n)
    decrypted = [pow(c, d, n) for c in ciphertext]
    #    - Convert to bytes and decode UTF-8
    return bytes(decrypted).decode("utf-8")


# from w1d4_test import test_encryption


# test_encryption(encrypt_rsa, decrypt_rsa, generate_keys)

pub, priv = generate_keys()
message = "Hello, world!"
encrypted = encrypt_rsa(pub, message)
decrypted = decrypt_rsa(priv, encrypted)


# %%
def add_pkcs7_padding(plaintext: bytes, block_size: int = 16) -> bytes:
    """
    Add PKCS#7 padding to plaintext.

    Args:
        plaintext: The data to pad
        block_size: The cipher block size

    Returns:
        Padded plaintext that is a multiple of block_size
    """
    text_len = len(plaintext)
    bytes_to_add = block_size - (text_len % block_size)
    text_with_padding = plaintext + (bytes([bytes_to_add]) * bytes_to_add)
    return text_with_padding


from w1d4_test import test_add_pkcs7_padding

test_add_pkcs7_padding(add_pkcs7_padding)


# %%
class InvalidPaddingError(Exception):
    """Raised when PKCS#7 padding is invalid."""

    pass


def remove_pkcs7_padding(padded_text: bytes, block_size: int = 16) -> bytes:
    """
    Remove and validate PKCS#7 padding.

    Args:
        padded_text: The padded data
        block_size: The cipher block size

    Returns:
        Original plaintext with padding removed

    Raises:
        InvalidPaddingError: If padding is invalid
    """
    text_len = len(padded_text)
    if text_len == 0:
        raise InvalidPaddingError

    padding_size = int(padded_text[text_len - 1])
    if padding_size > block_size or padding_size > text_len or padding_size == 0:
        raise InvalidPaddingError

    for i in range(padding_size):
        if int(padded_text[text_len - i - 1]) != padding_size:
            raise InvalidPaddingError

    return padded_text[:-padding_size]


from w1d4_test import test_remove_pkcs7_padding

test_remove_pkcs7_padding(remove_pkcs7_padding, InvalidPaddingError)

# %%


# %%
def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    assert len(a) == len(b), "Byte strings must have equal length"
    return bytes(x ^ y for x, y in zip(a, b))


def single_block_aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    assert len(plaintext) == 16, "Plaintext must be 16 bytes"
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Encrypt plaintext using AES in CBC mode.

    Args:
        plaintext: The message to encrypt (will be padded)
        key: AES key (16, 24, or 32 bytes)
        iv: Initialization vector (16 bytes)

    Returns:
        Ciphertext (same length as padded plaintext)
    """
    block_size = len(iv)
    padded_message = add_pkcs7_padding(plaintext, block_size=block_size)
    blocks = [
        padded_message[block_idx : block_idx + block_size] for block_idx in range(0, len(padded_message), block_size)
    ]

    prev_ciphertext = iv
    encrypted_blocks: list[bytes] = [] 
    for current_plaintext in blocks:
        xor_out = bytes([
            c ^ p for c, p in zip(prev_ciphertext, current_plaintext, strict=True)
        ])
        encrypt_out = single_block_aes_encrypt(xor_out, key)
        encrypted_blocks.append(encrypt_out)
        prev_ciphertext = encrypt_out

    return bytes(byte for block in encrypted_blocks for byte in block)


from w1d4_test import test_cbc_encrypt

test_cbc_encrypt(cbc_encrypt)
