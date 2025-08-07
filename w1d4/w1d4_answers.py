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
    # 1. Save original message length in bytes
    original_length = len(message)

    # 2. Append 0x80 (the '1' bit followed by zeros)
    message = bytearray(message)
    message.append(0x80)

    # 3. Pad with zero bytes until the size modulo 64 is 56
    while len(message) % 64 != 56:
        message.append(0)

    # 4. Convert original message length to bits and append as 64-bit little-endian
    bit_length = original_length * 8
    message += bit_length.to_bytes(8, "little")

    return bytes(message)


from w1d4_test import test_left_rotate
from w1d4_test import test_md5_padding_length
from w1d4_test import test_md5_padding_content


test_left_rotate(left_rotate)
test_md5_padding_length(md5_padding)
test_md5_padding_content(md5_padding)


# %%

bytes(0x10)


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
    print(block)
    splits = []
    for i in range(16):
        splits.append(bytes_to_int32_le(block, i * 4))
    print("splits")
    print(splits)
    # 2. Initialize A, B, C, D from state
    A, B, C, D = state
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
    for i in range(64):
        # Fix: Use proper round determination logic
        if i < 16:
            round_id = 0
        elif i < 32:
            round_id = 1
        elif i < 48:
            round_id = 2
        else:
            round_id = 3

        match round_id:
            case 0:
                k = i
                func = md5_f(B, C, D)
            case 1:
                k = (5 * i + 1) % 16
                func = md5_g(B, C, D)
            case 2:
                k = (3 * i + 5) % 16
                func = md5_h(B, C, D)
            case 3:
                k = (7 * i) % 16
                func = md5_i(B, C, D)

        # Fix: Use MD5_T[i] instead of MD5_T[k]
        temp = A + func + splits[k] + MD5_T[i]
        # Mask the value to the low 32 bits
        masked = temp & 0xFFFFFFFF
        # Left rotate the value by MD5_S[i] bits
        rotated = left_rotate(masked, MD5_S[i])
        # Fix: Add B to the rotated value and mask again
        temp = (B + rotated) & 0xFFFFFFFF
        # Fix: Use temp (not masked) in the rotation
        A, B, C, D = D, temp, B, C

    # Fix: Add the original state values to A, B, C, D before updating
    state[0] = (state[0] + A) & 0xFFFFFFFF
    state[1] = (state[1] + B) & 0xFFFFFFFF
    state[2] = (state[2] + C) & 0xFFFFFFFF
    state[3] = (state[3] + D) & 0xFFFFFFFF
    # 4. Return the new state:
    #    - add the resulting values of A, B, C, D to the respective values in the state given in the argument
    #    - e.g., state[0] = (state[0] + A)
    #    - mask the new state values to the low 32 bits
    return state


def md5_hash(message: bytes) -> bytes:
    """
    Compute MD5 hash of message.

    Args:
        message: Input message as bytes

    Returns:
        16-byte MD5 hash
    """
    if "SOLUTION":
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
    else:
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


# %%

a = [3, 235]

b, c = a

b += 3

print(a)
print(b)


# %%


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

    print(key)
    print("length?")
    print(len(key))

    if len(key) > block_size:
        hash = md5_hash(key)
    else:
        length = block_size - len(key)
        for _ in range(length):
            key += b"\x00"

    hash = md5_hash(bytes(ipad ^ k for k in key) + message)

    hmac = md5_hash(bytes(opad ^ k for k in key) + hash)

    return hmac

    # TODO: Implement HMAC-MD5

    # Step 1: Normalize the key length
    # - If key longer than block_size, hash it with md5_hash
    # - Otherwise, pad key to exactly block_size bytes with null bytes

    # Step 2: Compute inner hash
    # - compute Hash(ipad ⊕ key || message)
    # Hint: Use bytes(k ^ ipad for k in key) for XOR operation

    # Step 3: Compute HMAC
    # - compute Hash(opad ⊕ key || inner_hash)


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


from w1d4_test import test_hmac_md5
from w1d4_test import test_hmac_verify


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

    p = get_prime(bits // 2)
    q = get_prime(bits // 2)
    while q == p:
        q = get_prime(bits // 2)

    n = p * q
    totient = (p - 1) * (q - 1)

    e = 65537

    d = pow(e, -1, totient)

    return ((n, e), (n, d))

    # TODO: Implement key generation
    #    - Generate p and q (bits//2 each)
    #    - Ensure p ≠ q
    #    - Compute n and φ(n)
    #    - Choose e (check if coprime with φ)
    #    - Compute d using pow(e, -1, phi)
    pass


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
    #    - Convert message to bytes with .encode("utf-8")
    #    - Encrypt each byte with pow(byte, e, n)
    #    - Return list of encrypted values

    n, e = public_key

    message = message.encode("utf-8")

    cipher = [pow(byte, e, n) for byte in message]

    return cipher


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
    n, d = private_key

    decoded = [pow(c, d, n) for c in ciphertext]

    decoded = bytes(decoded)

    plain = decoded.decode("utf-8")

    return plain

    # TODO: Implement decryption
    #    - Extract n and d from private_key
    #    - Decrypt each value with pow(c, d, n)
    #    - Convert to bytes and decode UTF-8
    pass


from w1d4_test import test_encryption


test_encryption(encrypt_rsa, decrypt_rsa, generate_keys)
