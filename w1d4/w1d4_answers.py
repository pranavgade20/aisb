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
    mlength = len(message)
    message = message + b"\x80"
    while len(message) % 64 != 56:
        message = message + b"\x00"
    mlength_bits = 8 * mlength
    message = message + mlength_bits.to_bytes(8, byteorder="little")
    return message


from w1d4_test import test_left_rotate
from w1d4_test import test_md5_padding_length
from w1d4_test import test_md5_padding_content


# test_left_rotate(left_rotate)
# test_md5_padding_length(md5_padding)
# test_md5_padding_content(md5_padding)


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
    # 2. Initialize A, B, C, D from state
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
    #    - add the resulting values of A, B, C, D to the respective values in the state given in the argument
    #    - e.g., state[0] = (state[0] + A)
    #    - mask the new state values to the low 32 bits
    offset = 0
    wordlist = []
    for i in range(16):
        wordlist.append(bytes_to_int32_le(block, offset))
        offset += 4
    A, B, C, D = state
    for i in range(64):
        if i < 16:
            k = i
            temp = A + md5_f(B, C, D) + wordlist[k] + MD5_T[i]
        elif i < 32:
            k = (5 * i + 1) % 16
            temp = A + md5_g(B, C, D) + wordlist[k] + MD5_T[i]
        elif i < 48:
            k = (3 * i + 5) % 16
            temp = A + md5_h(B, C, D) + wordlist[k] + MD5_T[i]
        else:
            k = (7 * i) % 16
            temp = A + md5_i(B, C, D) + wordlist[k] + MD5_T[i]
        temp = temp & 0xFFFFFFFF
        rotatedb = left_rotate(temp, MD5_S[i]) + B
        masked_rotated = rotatedb & 0xFFFFFFFF
        A, B, C, D = D, masked_rotated, B, C
    final_list = [A, B, C, D]
    result = [x + y for x, y in zip(final_list, state)]
    masked_result = [x & 0xFFFFFFFF for x in result]
    return masked_result


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
    # 2. Pad the message using md5_padding() to make the length in bytes divisible by 64
    # 3. Process each 64-byte block:
    #    - For each block, apply the md5_process_block function to the block and the current state
    #    - Update the current state to be the result of md5_process_block
    # 4. Convert final state to bytes:
    #    - convert the state values to little-endian bytes
    #    - concatenate the bytes to get the final hash bytes
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    message = md5_padding(message)
    for i in range(len(message) // 64):
        block = message[64 * i : 64 * (i + 1)]
        state = md5_process_block(block, state)
    result = [x.to_bytes(4, byteorder="little") for x in state]
    return result[0] + result[1] + result[2] + result[3]


def md5_hex(message: bytes) -> str:
    """Compute MD5 hash and return as hex string."""
    return md5_hash(message).hex()


from w1d4_test import test_md5_process_block
from w1d4_test import test_md5

# test_md5_process_block(md5_process_block)
# test_md5(md5_hex)

# %%


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


# test_naive_mac(naive_mac, naive_verify)

# %%


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
    # TODO: Implement length extension attack
    # Step 1: Determine the "glue padding" that MD5 applied to (secret || original_message)
    # - The padding only depends on input length, not contents,
    #   therefore you can use a dummy value of secret_length + len(original_message) to construct input to md5_padding(),
    # - Extract just the padding part that was added as glue_padding

    dummy_secret = b"x" * secret_length
    padded_message = md5_padding(dummy_secret + original_message)
    padding = padded_message[len(original_message) + secret_length :]

    # Step 2: Build the forged message that the attacker will present as
    #   concatenation of original_message + glue_padding + additional_data
    forged_message = original_message + padding + additional_data

    # Step 3: Convert the original tag back to MD5 internal state
    # - The tag represents the MD5 state after processing (secret || original_message || glue_padding)
    # - Use bytes_to_int32_le to extract 4 32-bit words from the tag

    state = []
    for i in range(4):
        state.append(bytes_to_int32_le(original_tag, i * 4))

    # Step 4: Determine what final padding is needed
    # - Calculate total length: secret_length + len(original_message) + len(glue_padding) + len(additional_data)
    # - Create dummy data of that length and apply md5_padding()
    # - Extract the final padding that would be added

    total_len = secret_length + len(original_message) + len(padding) + len(additional_data)
    padded_dummy = md5_padding(b"X" * total_len)
    final_padding = padded_dummy[total_len:]

    # Step 5: Continue MD5 processing from the known state
    # - Process (additional_data + final_padding) starting from the extracted state
    # - Use md5_process_block for each 64-byte block

    data = additional_data + final_padding
    for i in range(0, len(data), 64):
        block = data[i : i + 64]
        if len(block) == 64:
            state = md5_process_block(block, state)

    # Step 6: Convert final state back to bytes for the forged tag
    forged_tag = b""
    for item in state:
        forged_tag += int32_to_bytes_le(item)

    return forged_message, forged_tag


from w1d4_test import test_length_extension_attack


# test_length_extension_attack(length_extension_attack, naive_mac, naive_verify)

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
    # - Otherwise, pad key to exactly block_size bytes with null bytes
    if len(key) > block_size:
        key = md5_hash(key)
    else:
        key = key + b"\x00" * (block_size - len(key))

    # Step 2: Compute inner hash
    # - compute Hash(ipad ⊕ key || message)
    # Hint: Use bytes(k ^ ipad for k in key) for XOR operation
    inner_hash = md5_hash(bytes(k ^ ipad for k in key) + message)

    # Step 3: Compute HMAC
    # - compute Hash(opad ⊕ key || inner_hash)
    return md5_hash(bytes(k ^ opad for k in key) + inner_hash)


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

from w1d4_test import test_hmac_security

test_hmac_security(hmac_md5, length_extension_attack, hmac_verify)

# %%
import random
from typing import Tuple, List


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
    # TODO: Implement key generation
    #    - Generate p and q (bits//2 each)
    #    - Ensure p ≠ q
    #    - Compute n and φ(n)
    #    - Choose e (check if coprime with φ)
    #    - Compute d using pow(e, -1, phi)
    p = get_prime(bits//2)
    q = get_prime(bits//2)
    while p==q:
        q = get_prime(bits//2)
    n = p*q
    totient = (p-1)*(q-1)
    e = 65537
    if math.gcd(e,totient) != 1:
        e = get_prime(5)
    d = pow(e, -1, totient)
    return ((n,e,), (n,d))

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
    n,e = public_key
    message = bytes(message, "utf-8")
    bytelist = []
    for b in message:
        bytelist.append(pow(b, e, n))
    return bytelist


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
    n,d = private_key
    byteslist = []
    for value in ciphertext:
        byteslist.append(pow(value,d,n))
    return bytes(byteslist).decode("utf-8")

from w1d4_test import test_encryption
test_encryption(encrypt_rsa, decrypt_rsa, generate_keys)

# %%
def sign(private_key: Tuple[int, int], message: str) -> List[int]:
    """Sign a UTF-8 message by raising bytes to the private exponent.

    Similar to decryption but applied to plaintext:
    1. Convert message to bytes
    2. For each byte m, compute s = m^d mod n
    3. Return list of signature values

    Args:
        private_key: Tuple (n, d) of modulus and private exponent
        message: The message to sign

    Returns:
        List of signature integers (one per byte)
    """
    n,d = private_key
    message = bytes(message,"utf-8")
    siglist = []
    for m in message:
        siglist.append(m**d % n)
    return siglist
    # TODO: Implement signing
    #    - Extract n and d from private_key
    #    - Convert message to bytes
    #    - Sign each byte with pow(byte, d, n)


def verify(public_key: Tuple[int, int], message: str, signature: List[int]) -> bool:
    """Verify an RSA signature.

    Steps:
    1. For each signature value s, compute m = s^e mod n
    2. Check if recovered values match original message bytes
    3. Handle invalid signatures gracefully

    Args:
        public_key: Tuple (n, e) of modulus and public exponent
        message: The original message
        signature: List of signature values to verify

    Returns:
        True if signature is valid, False otherwise
    """
    n,e = public_key
    message = bytes(message,"utf-8")
    for i in range(len(signature)):
        s = signature[i]
        m = s**e % n
        if message[i] != m:
            return False
    return True

    # TODO: Implement verification
    #    - Extract n and e from public_key
    #    - Recover each byte with pow(s, e, n)
    #    - Check if recovered bytes match original message
    #    - Return False for any errors
from w1d4_test import test_signatures
test_signatures(sign, verify, generate_keys)

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
    # TODO: Implement PKCS#7 padding according to the spec above
    n = block_size - (len(plaintext) % block_size)
    if n == 0:
        n=16
    padtext = plaintext+bytes([n]*n)
    return padtext
    
from w1d4_test import test_add_pkcs7_padding


test_add_pkcs7_padding(add_pkcs7_padding)# %%

# %%
# %%
class InvalidPaddingError(Exception):
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
    # TODO: Implement PKCS#7 unpadding with validation
    if len(padded_text) == 0:
        raise InvalidPaddingError
    padlength = padded_text[-1]
    if padded_text[-1] < 1 or padded_text[-1] > 16:
        raise InvalidPaddingError
    if len(padded_text) < padlength:
        raise InvalidPaddingError
    for i in range(padlength):
        if padded_text[-(i+1)] != padlength:
            raise InvalidPaddingError
    return padded_text[:-padlength]
        
from w1d4_test import test_remove_pkcs7_padding
test_remove_pkcs7_padding(remove_pkcs7_padding, InvalidPaddingError)

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
    plaintext = add_pkcs7_padding(plaintext)
    ciphertext = b""
    prev_block = iv

    for i in range(0,len(plaintext),16):
        plainblock = plaintext[i:i+16]
        postxor = xor_bytes(plainblock,prev_block)
        encrypted_block = single_block_aes_encrypt(postxor,key)
        ciphertext += encrypted_block
        prev_block = encrypted_block
    return ciphertext

from w1d4_test import test_cbc_encrypt


test_cbc_encrypt(cbc_encrypt)

# %%
