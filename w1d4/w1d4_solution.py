# %%
"""
# W1D4 - Cryptography 2: Hashing, RSA, Breaking Block Ciphers

Today you'll learn more about fundamental cryptographic primitives and discover their vulnerabilities. You'll build MD5, implement HMAC, create RSA key pairs, and execute padding oracle attacks - gaining deep insight into both offensive and defensive cryptography.


<!-- toc -->

## Content & Learning Objectives

### 1️⃣ Cryptographic Hashing and HMAC
You'll implement MD5 from scratch, discover length extension attacks, and build proper HMAC authentication.

> **Learning Objectives**
> - Understand how cryptographic hash functions work internally
> - Learn about Message Authentication Codes and their vulnerabilities
> - Implement secure HMAC according to RFC 2104
> - Explore password storage evolution and economics

### 2️⃣ RSA Public Key Cryptography
You'll generate RSA keys, implement encryption/decryption, and create digital signatures.

> **Learning Objectives**
> - Understand the mathematical foundation of RSA
> - Implement secure key generation and cryptographic operations
> - Learn about digital signatures and their properties

### 3️⃣ Padding Oracle Attacks
You'll implement CBC mode encryption and execute the famous padding oracle attack.

> **Learning Objectives**
> - Understand block cipher modes and padding schemes
> - Create and exploit padding oracle vulnerabilities
> - Learn about real-world attacks like POODLE

"""

# %%
"""
## 1️⃣ Cryptographic Hashing and HMAC

Cryptographic hash functions are one-way mathematical functions that take an input of arbitrary length and produce a fixed-size output called a hash or digest.
MD5 (Message Digest 5) is a widely known hash function that produces a 128-bit hash value, typically represented as a 32-character hexadecimal string.
Designed by Ron Rivest in 1991, MD5 was initially used for verifying data integrity and creating digital signatures.
The algorithm processes input data in 512-bit blocks through four rounds of operations, mixing the data thoroughly to ensure that even a single bit change in the input produces a completely different hash.
However, MD5 is now considered cryptographically broken due to discovered vulnerabilities that allow attackers to find collisions (different inputs producing the same hash) relatively easily.
Despite being unsuitable for security applications, MD5 still sees use in non-cryptographic contexts like checksums for file integrity verification.

**HMAC (Hash-based Message Authentication Code)** is a construction that combines a cryptographic hash function with a secret key to provide both data integrity and authentication.
Unlike simple hashing, HMAC proves not only that data hasn't been tampered with, but also that it came from someone possessing the secret key.
The HMAC algorithm works by processing the key and message through the hash function in a specific way: HMAC(K,m) = H((K ⊕ opad) || H((K ⊕ ipad) || m)), where H is the hash function, K is the secret key, and ipad/opad are specific padding constants.
This double hashing with the key provides security even if the underlying hash function has certain weaknesses.
HMAC is widely used in various security protocols including TLS, IPsec, and API authentication schemes.
Importantly, even though MD5 is broken for collision resistance, HMAC-MD5 remains relatively secure for message authentication, though HMAC with stronger hash functions like SHA-256 is preferred for new applications.

### Why Hashing Matters

Cryptographic hash functions are everywhere in security:
- **Password storage**: Never store passwords in plaintext!
- **Data integrity**: Detect if files have been tampered with
- **Digital signatures**: Verify authenticity of messages
- **Blockchain**: Proof-of-work and linking blocks
- **API authentication**: Secure communication without sending secrets

What makes cryptographic hash functions useful for security are these properties:

1. **Deterministic**: The same input always produces the same output.
2. **Collision resistance**: It's computationally infeasible to find two different inputs that produce the same hash output.
3. **Avalanche effect**: A tiny change to the input (even flipping a single bit) causes a large, unpredictable change in the output. Roughly half the output bits should flip, ensuring full keyspace utilization.
4. **One-way (non-invertible)**: Given a hash output, it's computationally infeasible to find the original input.

<details>
<summary>Vocabulary: Cryptographic Hash Terms</summary>

- **Hash function**: A mathematical function that maps data of arbitrary size to fixed-size values
- **Digest**: The output of a hash function, also called a hash value or hash
- **Collision**: When two different inputs produce the same hash output
- **Preimage attack**: Finding an input that produces a given hash output
- **Birthday attack**: Finding any two inputs that produce the same hash (exploits birthday paradox)

</details>

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

# %%
"""
### Exercise 1.1: Implementing MD5

> **Difficulty**: 🔴🔴⚪⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪


You'll implement MD5 from scratch to understand how cryptographic hash functions work internally. This involves bit manipulation, modular arithmetic, and careful attention to detail.

#### MD5 Algorithm Overview

MD5 processes data in 512-bit blocks and produces a 128-bit hash. On a high level, it does:
1. Pads the message so that its length in bits is divisible by 512
2. Initializes a 4 32-bit word state (A, B, C, D)
3. Processes the message in 512-bit blocks, updating the state after each block
4. Concatenates the final state bytes to produce the final 128-bit hash.

Processing of each 512-bit block involves updating the state in 64 rounds. 
Each round uses one of four auxiliary functions (F, G, H, I) and follows this pattern:
```
A, B, C, D = D, (B + left_rotate((A + F(B,C,D) + X[k] + T[i]), s)), B, C
```
Where:
- F, G, H, I are bitwise functions operating on B, C, D
- X[k] is a 32-bit word from the current message block
- T[i] is a pre-computed constant
- s is a rotation amount

Don't worry if this seems complex - you'll implement it step by step!


#### MD5 Building Blocks
"""


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
MD5_T = [
    int(math.floor((2**32) * abs(math.sin(i + 1)))) & 0xFFFFFFFF for i in range(64)
]

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
    return (
        data[offset]
        | (data[offset + 1] << 8)
        | (data[offset + 2] << 16)
        | (data[offset + 3] << 24)
    )


def int32_to_bytes_le(value: int) -> bytes:
    """Convert 32-bit integer to 4 bytes in little-endian format."""
    return bytes(
        [value & 0xFF, (value >> 8) & 0xFF, (value >> 16) & 0xFF, (value >> 24) & 0xFF]
    )


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
    if "SOLUTION":
        msg_len = len(message)
        message += b"\x80"  # Append '1' bit

        # Pad with zeros until length ≡ 448 bits mod 512 (i.e., 56 bytes mod 64)
        # the formula below is equivalent (divided by 8 to convert to bytes)
        while len(message) % 64 != 56:
            message += b"\x00"

        # Append original length as 64-bit little-endian (bit length)
        bit_length = msg_len * 8

        message += int64_to_bytes_le(bit_length)

        return message
    else:
        # TODO: Implement MD5 padding
        # 1. Save original message length in bytes
        # 2. Append 0x80 (the '1' bit)
        # 3. Pad with zero bytes until the size modulo 64 is 56
        # 4. Convert message length to bits
        # 5. Append bit-length as 64-bit little-endian
        pass


@report
def test_left_rotate(solution: Callable[[int, int], int]):
    """Test left_rotate implementation with known test cases."""
    test_cases = [
        # (value, amount, expected_result)
        # Basic cases
        (0x00000001, 1, 0x00000002),  # 1 rotated left by 1 = 2
        (0x00000001, 31, 0x80000000),  # 1 rotated left by 31 = MSB set
        (0x80000000, 1, 0x00000001),  # MSB rotated left by 1 wraps to LSB
        # Edge cases
        (0x00000000, 15, 0x00000000),  # Zero rotated by any amount = zero
        (
            0xFFFFFFFF,
            8,
            0xFFFFFFFF,
        ),  # All bits set rotated by any amount = all bits set
        (0x12345678, 0, 0x12345678),  # Rotate by 0 = no change
        # More complex rotations
        (0x12345678, 4, 0x23456781),  # Rotate 0x12345678 left by 4
        (0x12345678, 8, 0x34567812),  # Rotate 0x12345678 left by 8
        (0x12345678, 16, 0x56781234),  # Rotate 0x12345678 left by 16
        (0x12345678, 32, 0x12345678),  # Rotate by 32 = full rotation = no change
        # Test wraparound behavior
        (0xF0000000, 4, 0x0000000F),  # High nibble wraps to low nibble
        (0x0000000F, 28, 0xF0000000),  # Low nibble wraps to high nibble
    ]

    for value, amount, expected in test_cases:
        result = solution(value, amount)
        assert result == expected, (
            f"left_rotate(0x{value:08X}, {amount}) = 0x{result:08X if result is not None else None}, expected 0x{expected:08X}"
        )


@report
def test_md5_padding_length(solution: Callable[[bytes], bytes]):
    """Test MD5 padding implementation with basic cases."""
    test_cases = [
        # (message, expected_length)
        (b"", 64),  # Empty message pads to 64 bytes
        (b"a", 64),  # Single byte pads to 64 bytes
        (b"a" * 55, 64),  # 55 bytes pads to 64 bytes
        (b"a" * 56, 128),  # 56 bytes needs new block, pads to 128 bytes
        (b"a" * 119, 128),
        (b"a" * 120, 192),
    ]

    for message, expected_len in test_cases:
        result = solution(message)
        assert len(result) % 64 == 0, (
            f"Padded length must be multiple of 64, got {len(result)}"
        )
        assert len(result) == expected_len, (
            f"Padding {len(message)} bytes should result in {expected_len} bytes, got {len(result)}"
        )


@report
def test_md5_padding_content(solution: Callable[[bytes], bytes]):
    """Test MD5 padding implementation with basic cases."""
    test_cases = [
        (b"", b"\x80" + b"\x00" * 63),
        (b"abc", b"abc" + b"\x80" + b"\x00" * 52 + b"\x18\x00\x00\x00\x00\x00\x00\x00"),
    ]
    for message, expected in test_cases:
        result = solution(message)
        assert result == expected, (
            f"Padding {message:x} = {result:x}, expected {expected:x}"
        )


test_left_rotate(left_rotate)
test_md5_padding_length(md5_padding)
test_md5_padding_content(md5_padding)

"""
<details>
<summary>Hint</summary>
When appending the the '1' bit 0x80, make sure you are indeed appending only one bit, not an integer. You can use, e.g., `b"\x80"`.
</details>

"""

# %%
"""
#### MD5 Implementation
"""


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
    if "SOLUTION":
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
    else:
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
        pass


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


@report
def test_md5_process_block(solution: Callable[[bytes, list], list]):
    """Test MD5 process_block with basic sanity checks."""
    # MD5 initial state
    initial_state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    test_cases = [
        # (block, input_state, expected_result)
        (
            b"\x00" * 64,
            initial_state.copy(),
            [0x031F1DAC, 0x6EA58ED0, 0x1FAB67B7, 0x74317791],
        ),  # All-zero block
        (
            b"a" * 64,
            initial_state.copy(),
            [0x89D4FF56, 0x125CD962, 0x69CADE33, 0x33E325],
        ),  # Block with repeated 'a'
    ]

    for block, state, expected in test_cases:
        result = solution(block, state)

        # Check that result is a list of 4 integers
        assert isinstance(result, list), f"Expected list, got {type(result)}"
        assert len(result) == 4, f"Expected 4 state values, got {len(result)}"

        # Check that all values are 32-bit integers
        for i, val in enumerate(result):
            assert isinstance(val, int), f"State[{i}] should be int, got {type(val)}"
            assert 0 <= val <= 0xFFFFFFFF, (
                f"State[{i}] = 0x{val:X} is not a 32-bit value"
            )

        assert result == expected, (
            f"md5_process_block({block}, [{', '.join([f'0x{x:X}' for x in state])}]) = [{', '.join([f'0x{x:X}' for x in result])}], expected [{', '.join([f'0x{x:X}' for x in expected])}]"
        )


@report
def test_md5(solution: Callable[[bytes], str]):
    """Test MD5 implementation with known vectors."""
    test_cases = [
        (b"", "d41d8cd98f00b204e9800998ecf8427e"),
        (b"a", "0cc175b9c0f1b6a831c399e269772661"),
        (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
        (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        (b"abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
        (
            b"The quick brown fox jumps over the lazy dog",
            "9e107d9d372bb6826bd81d3542a419d6",
        ),
    ]

    for message, expected in test_cases:
        result = solution(message)
        assert result == expected, (
            f"MD5({message:x}) = {result:x}, expected {expected:x}"
        )
        print(f"✅ md5({message!r}) = {result}")


test_md5_process_block(md5_process_block)
test_md5(md5_hex)

# %%
"""
### Understanding MD5's Structure

Now that you've implemented MD5, let's explore what makes it tick:

**Why These Design Choices?**

1. **Block-based processing**: Handles arbitrary-length input efficiently
2. **Four rounds with different functions**: Provides diffusion - small input changes affect the entire output
3. **Message scheduling**: Each round uses message words in different orders for better mixing
4. **Modular addition and rotation**: Creates nonlinear relationships that are hard to reverse

**The Merkle-Damgård Construction**

MD5 follows the Merkle-Damgård construction:
```
Hash = H(H(H(H(IV, Block1), Block2), Block3), ...)
```

(IV is an "initialization vector" - the initial state. For MD5, IV consists of four 32-bit magic constants.)

This design has a crucial property: if the compression function (processing one block) is collision-resistant, then the entire hash function is collision-resistant.

**But what happens when that assumption breaks?**

Let's explore MD5's vulnerabilities in the next exercise...
"""

# %%
"""
### Finding MD5 Collisions

MD5 is cryptographically broken - it's possible to find two different messages that produce the same hash. While finding collisions from scratch requires sophisticated techniques, we can demonstrate the impact using known collision pairs.

**Why Collisions Matter**

Hash collisions break the fundamental assumption that different inputs produce different outputs. When attackers can find two different messages with the same hash, they can perform devastating attacks that bypass security systems relying on hash uniqueness.

Many security systems assume that if two strings or files have the same hash, they must be identical. Collisions break this assumption, allowing attackers to substitute malicious content while maintaining the same hash value.

Examples of attack scenarios:

- **Certificate forgery**: Creating fake SSL certificates with same hash as legitimate ones. An attacker can generate a malicious certificate that has the same MD5 hash as a trusted certificate, potentially allowing them to impersonate websites or services.

- **Software tampering**: Replace legitimate software with malware that has the same hash. If software distribution relies on MD5 checksums for integrity verification, attackers can create malicious versions that pass integrity checks.

- **Document forgery**: Create contracts or other documents with the same hash but different content. An attacker could create two versions of a contract - one benign for initial review and signing, another malicious with the same hash for later substitution.

- **Password attacks**: Find alternative passwords that hash to the same value. While less practical due to salting in modern systems, this could potentially bypass authentication in poorly designed systems.

#### Demonstrating MD5 Collisions

Finding a new MD5 collision can take hours to days, therefore we'll limit ourselves to demonstrating an existing collision:
"""

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
"""
#### Real-World Impact

MD5 has been cryptographically broken since 2004. 
Practical exploits are available since 2008 when the first rogue CA certificate was forged by Stevens et al.

MD5-based certificates were universally rejected by browsers and operating systems only by early 2014. The weakness in MD5 was exploited, e.g., by [Flame malware](https://en.wikipedia.org/wiki/Flame_(malware)) (2012), where a nation-state actor used MD5 collisions to forge Microsoft certificates, making the malware appear to be legitimate Microsoft software.

#### Modern Alternatives

Because of these vulnerabilities, MD5 should never be used for security purposes. Modern alternatives include:
- **SHA-256**: Part of SHA-2 family, no known practical attacks
- **SHA-3**: Different construction from SHA-2, provides additional security margin  
- **BLAKE3**: Modern, fast, and secure hash function

However, MD5 is still acceptable for non-security uses like checksums for data corruption detection.

In the next exercise, we'll see how hash functions are used to build authentication systems...
"""

# %%
"""
### Exercise 1.2: Breaking a naive Message Authentication Code

Now that you understand how hash functions work internally, let's explore how they're used to build secure authentication systems. You'll discover why naive approaches fail in this exercise, and build a proper HMAC implementation in the next one.

> **Difficulty**: 🔴🔴⚪⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪

**What are Message Authentication Codes?**

Message authentication codes (MACs) ensure two critical properties:
1. **Integrity**: The message hasn't been modified
2. **Authentication**: The message came from someone who knows a shared secret

Unlike encryption, MACs doesn't hide the message content - it just proves the message is authentic and untampered.

[HMAC](https://en.wikipedia.org/wiki/HMAC), or "hashed-based message authentication code", 
is a type of MAC based on a cryptographic hash function and a secret key.

A piece of data that provides authentication and integrity verification is also known as a *tag* (analogous to a *signature* in asymmetric cryptography).

<details>
<summary>Vocabulary: Authentication Terms</summary>

- **MAC (Message Authentication Code)**: A cryptographic checksum that provides both integrity and authenticity
- **HMAC (Hash-based Message Authentication Code)**: Kind of MAC based on a cryptographic hash and a secret key
- **Tag**: The output of a MAC function, proves the message is authentic
- **Authentication**: Verifying that a message comes from a claimed sender
- **Integrity**: Ensuring that data has not been modified or corrupted
- **Shared secret**: A confidential key shared by communicating parties
- **Replay attack**: Retransmitting a valid data transmission maliciously

</details>

#### Real-World Uses
HMAC is everywhere in modern security:

- **API Authentication**: Services like AWS use HMAC signatures to authenticate API requests
- **JWT Tokens**: JSON Web Tokens use HMAC to prevent tampering with claims
- **Cookie Signing**: Web frameworks use HMAC to detect tampered session cookies  
- **Webhook Verification**: GitHub, Stripe, etc. use HMAC to verify webhook authenticity
"""
# %%

"""
#### Naive Approach: Hash with Secret

HMAC relies on a shared secret key. Since a good hash function is one-way, it's not possible to recover the secret from the hash when we combine it with the message before hashing. The most straightforward approach is thus to just concatenate the message with the secret, and hash the result.

This provides two desired security properties: **Integrity** - any modification to the message will produce a completely different HMAC due to the avalanche effect, making tampering detectable. **Authentication** - only parties who know the shared secret can generate valid HMACs; given a message, the validator generates the expected HMAC and compares it with the received one; a match proves the message came from a legitimate source.
"""


def naive_mac(message: bytes, secret: bytes) -> bytes:
    """
    Naive message authentication: Hash(secret || message)

    Args:
        message: The message to authenticate
        secret: Secret key known only to legitimate parties
    Returns:
        Authentication tag
    """
    if "SOLUTION":
        return md5_hash(secret + message)
    else:
        # TODO: Implement naive MAC
        # Concatenate secret and message, then hash the result
        # Use the md5_hash function you implemented earlier
        pass


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
    if "SOLUTION":
        expected_tag = naive_mac(message, secret)
        return expected_tag == tag
    else:
        # TODO: Implement naive verification
        # Compute the expected tag for the message and compare it with the provided tag
        pass


@report
def test_naive_mac(
    naive_mac_func: Callable[[bytes, bytes], bytes],
    naive_verify_func: Callable[[bytes, bytes, bytes], bool],
):
    """
    Test naive MAC implementation for basic functionality.
    First test properties that the functions should have in general,
    then test the expected concrete values because we need the implementation to match for the subsequent exercises
    """
    secret = b"super_secret_key"
    message1 = b"Hello, World!"
    message2 = b"Hello, World2!"  # Different message

    # Test that MAC produces deterministic results
    tag1_a = naive_mac_func(message1, secret)
    tag1_b = naive_mac_func(message1, secret)
    assert tag1_a == tag1_b, "MAC should be deterministic"

    # Test that different messages produce different MACs
    tag1 = naive_mac_func(message1, secret)
    tag2 = naive_mac_func(message2, secret)
    assert tag1 != tag2, "Different messages should produce different MACs"

    # Test that verification works for legitimate messages
    assert naive_verify_func(message1, secret, tag1), (
        "Should verify correct message/tag pair"
    )
    assert naive_verify_func(message2, secret, tag2), (
        "Should verify correct message/tag pair"
    )

    # Test that verification fails for wrong message/tag combinations
    assert not naive_verify_func(message1, secret, tag2), (
        "Should reject wrong message/tag pair"
    )
    assert not naive_verify_func(message2, secret, tag1), (
        "Should reject wrong message/tag pair"
    )

    # Test that different secrets produce different MACs
    different_secret = b"different_secret"
    tag_different_secret = naive_mac_func(message1, different_secret)
    assert tag1 != tag_different_secret, (
        "Different secrets should produce different MACs"
    )
    assert not naive_verify_func(message1, different_secret, tag1), (
        "Should reject MAC with wrong secret"
    )

    # Assert concrete values:
    naive_mac_result = naive_mac_func(b"abc", b"s3cr3t")
    naive_mac_expected = bytes.fromhex("ebd4a9ce960be8386347977e81a12252")
    assert naive_mac_result == naive_mac_expected, (
        f"naive_mac('abc', 's3cr3t') = {naive_mac_result.hex()}, expected {naive_mac_expected.hex()}"
    )


test_naive_mac(naive_mac, naive_verify)

# %%
"""
#### Breaking the Naive Approach: Length Extension Attack

The naive approach has a critical flaw: vulnerability to **length extension attacks**. The vulnerability follows from the MD5's Merkle-Damgård construction. 
You'll find the explanation in the following text toggle, but you can also try to figure it out yourself if you want a challenge!

<details>
<summary>How length extension against Merkle-Damgård construction works</summary>
If you know Hash(A), you can compute Hash(A || B) for any B without knowing A!

This happens because:
1. MD5 processes data in blocks and maintains internal state
2. The final hash is just the internal state after processing all blocks
3. An attacker can use the known hash as the starting state for additional blocks

</details>


#### Implementing Length Extension Attack

Given `Hash(message || secret)` and the length of `(message || secret)`, an attacker can compute `Hash(message || secret || padding || additional_data)` even without knowing the secret.

Think for a moment how you would implement the technical details:
- How would you determine the "glue padding" that MD5 appended to (message || secret)?
- How can you get the 4 values of the internal state that correspond to the internal state after processing (message || secret)?
- What's remaining to be done to compute the final hash once you have the glue padding and internal state?
"""


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
    if "SOLUTION":
        # Step 1: Figure out what padding was applied to (secret || original_message)
        dummy_secret = b"X" * secret_length
        padded_dummy = md5_padding(dummy_secret + original_message)
        original_length = secret_length + len(original_message)
        glue_padding = padded_dummy[original_length:]  # This is the padding MD5 added

        # Step 2: The forged message visible to the verifier
        # This is what an attacker presents: original_message || glue_padding || additional_data
        forged_message = original_message + glue_padding + additional_data

        # Step 3: Convert the original tag to MD5 internal state
        # The original_tag represents the state after processing (secret || original_message || glue_padding)
        state = []
        for i in range(4):
            word = bytes_to_int32_le(original_tag, i * 4)
            state.append(word)

        # Step 4: Continue hashing from the known state
        # We need to process (additional_data || final_padding)
        # The total message being hashed is: secret || original_message || glue_padding || additional_data
        total_length = (
            secret_length
            + len(original_message)
            + len(glue_padding)
            + len(additional_data)
        )

        # Determine what final padding is needed
        temp_data = b"X" * total_length
        fully_padded = md5_padding(temp_data)
        final_padding = fully_padded[total_length:]

        # Step 5: Process additional_data || final_padding starting from known state
        remaining_data = additional_data + final_padding

        for i in range(0, len(remaining_data), 64):
            block = remaining_data[i : i + 64]
            if len(block) == 64:  # Only process complete 64-byte blocks
                state = md5_process_block(block, state)

        # Step 6: Convert final state back to bytes
        forged_tag = b""
        for word in state:
            forged_tag += int32_to_bytes_le(word)

        return forged_message, forged_tag
    else:
        # TODO: Implement length extension attack
        # Step 1: Determine the "glue padding" that MD5 applied to (secret || original_message)
        # - The padding only depends on input length, not contents,
        #   therefore you can use a dummy value of secret_length + len(original_message) to construct input to md5_padding(),
        # - Extract just the padding part that was added as glue_padding

        # Step 2: Build the forged message that the attacker will present as
        #   concatenation of original_message + glue_padding + additional_data

        # Step 3: Convert the original tag back to MD5 internal state
        # - The tag represents the MD5 state after processing (secret || original_message || glue_padding)
        # - Use bytes_to_int32_le to extract 4 32-bit words from the tag

        # Step 4: Determine what final padding is needed
        # - Calculate total length: secret_length + len(original_message) + len(glue_padding) + len(additional_data)
        # - Create dummy data of that length and apply md5_padding()
        # - Extract the final padding that would be added

        # Step 5: Continue MD5 processing from the known state
        # - Process (additional_data + final_padding) starting from the extracted state
        # - Use md5_process_block for each 64-byte block

        # Step 6: Convert final state back to bytes for the forged tag

        pass


@report
def test_length_extension_attack(
    length_extension_attack: Callable[[bytes, bytes, int, bytes], tuple[bytes, bytes]],
    naive_mac: Callable[[bytes, bytes], bytes],
    naive_verify: Callable[[bytes, bytes, bytes], bool],
):
    """Show how length extension breaks the naive MAC."""
    secret = b"secret1234567890"  # Attacker doesn't know this
    original_message = b"user=alice&action=view"
    malicious_data = b"&action=admin"  # Attacker wants to append malicious data

    # Legitimate MAC
    original_tag = naive_mac(original_message, secret)
    print("Length Extension Attack\n" + "=" * 50)
    print(f"Original message: {original_message}")
    print(f"Original MAC:     {original_tag.hex()}")
    print(f"Secret length:    {len(secret)} (attacker might guess this)")
    print(f"Malicious suffix: {malicious_data}")
    print()

    # Perform length extension attack
    forged_message, forged_tag = length_extension_attack(
        original_message, original_tag, len(secret), malicious_data
    )

    print(f"Forged message: {forged_message}")
    print(f"Forged MAC:     {forged_tag.hex()}")
    print()

    # Verify the forged MAC is actually valid!
    is_valid = naive_verify(forged_message, secret, forged_tag)
    assert is_valid, "Forged MAC should be accepted by naive_verify"
    print(f"Forged MAC validates: 🚨 {is_valid}")
    print("💥 The attacker created a valid MAC without knowing the secret!")
    print(
        f"This could let them escalate '{original_message.decode()}' to admin privileges!"
    )


test_length_extension_attack(length_extension_attack, naive_mac, naive_verify)

# %%
"""
### Exercise 1.3: Building proper HMAC implementation

The length extension attack shows why we need a more sophisticated approach. 
We are going to implement HMAC according to RFC 2104 to see how it addresses the problem using a clever construction.

> **Difficulty**: 🔴🔴🔴⚪⚪  
> **Importance**: 🔵🔵🔵🔵🔵


**HMAC Construction**

HMAC works by hashing twice with different keys:

```
HMAC(key, message) = Hash(opad ⊕ key || Hash(ipad ⊕ key || message))
```

Where:
- `ipad` = 0x36 repeated for block size (inner padding)
- `opad` = 0x5C repeated for block size (outer padding)  
- `key` is the secret key normalized to the hash function's block size 
- `⊕` is XOR operation
- `||` is concatenation

**Why This Design Works**

1. **Two hash calls**: Even if you can extend the inner hash, you can't extend the outer hash without knowing the key
2. **Different keys**: The inner and outer keys are different (key ⊕ ipad vs key ⊕ opad)
3. **No state leakage**: The final hash doesn't reveal the intermediate state
4. **Key length doesn't weaken security**: normalizing the key length prevents prevents key length attacks  and maintains entropy distribution

Let's implement it:
"""


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

    if "SOLUTION":
        # Step 1: Prepare the key
        if len(key) > block_size:
            key = md5_hash(key)
        if len(key) < block_size:
            key = key + b"\x00" * (block_size - len(key))

        # Step 2: Create inner hash
        inner_key = bytes(k ^ ipad for k in key)  # key ⊕ ipad
        inner_hash = md5_hash(inner_key + message)

        # Step 3: Compute outer hash
        outer_key = bytes(k ^ opad for k in key)  # key ⊕ opad
        outer_hash = md5_hash(outer_key + inner_hash)

        return outer_hash
    else:
        # TODO: Implement HMAC-MD5

        # Step 1: Normalize the key length
        # - If key longer than block_size, hash it with md5_hash
        # - Otherwise, pad key to exactly block_size bytes with null bytes

        # Step 2: Compute inner hash
        # - compute Hash(ipad ⊕ key || message)
        # Hint: Use bytes(k ^ ipad for k in key) for XOR operation

        # Step 3: Compute HMAC
        # - compute Hash(opad ⊕ key || inner_hash)
        pass


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


@report
def test_hmac_md5(hmac_md5_func: Callable[[bytes, bytes], bytes]):
    """Test HMAC-MD5 implementation with known test vectors and basic functionality."""

    # Test basic functionality
    key = b"test_key"
    message1 = b"Hello, World!"
    message2 = b"Hello, World2!"  # Different message

    # Test that HMAC produces deterministic results
    hmac1_a = hmac_md5_func(key, message1)
    hmac1_b = hmac_md5_func(key, message1)
    assert hmac1_a == hmac1_b, "HMAC should be deterministic"

    # Test that different messages produce different HMACs
    hmac2 = hmac_md5_func(key, message2)
    assert hmac1_a != hmac2, "Different messages should produce different HMACs"

    # Test that different keys produce different HMACs
    different_key = b"different_key"
    hmac_different_key = hmac_md5_func(different_key, message1)
    assert hmac1_a != hmac_different_key, (
        "Different keys should produce different HMACs"
    )

    # Test that HMAC produces 16-byte output (MD5 hash length)
    assert len(hmac1_a) == 16, (
        f"HMAC-MD5 should produce 16-byte output, got {len(hmac1_a)}"
    )

    # Test with RFC 2202 test vectors
    rfc_test_cases = [
        # (key, message, expected_hmac_hex)
        (b"\x0b" * 16, b"Hi There", "9294727a3638bb1c13f48ef8158bfc9d"),
        (b"Jefe", b"what do ya want for nothing?", "750c783e6ab0b503eaa86e310a5db738"),
        (b"\xaa" * 16, b"\xdd" * 50, "56be34521d144c88dbb8c733f0e8b3f6"),
    ]

    for i, (test_key, test_message, expected_hex) in enumerate(rfc_test_cases):
        result = hmac_md5_func(test_key, test_message)
        result_hex = result.hex()
        assert result_hex == expected_hex, (
            f"hmac_md5({test_key!r}, {test_message!r}) = {result_hex}, expected {expected_hex}"
        )


@report
def test_hmac_verify(hmac_verify_func: Callable[[bytes, bytes, bytes], bool]):
    """Test HMAC verification function using Python's built-in hmac implementation as reference."""
    key = b"test_secret_key"
    message = b"Hello, HMAC verification!"
    expected_hmac = hmac.new(key, message, hashlib.md5).digest()

    # Test that correct HMAC verifies successfully
    assert hmac_verify_func(key, message, expected_hmac), "Should verify correct HMAC"

    # Test that verification fails with wrong key
    wrong_key = b"wrong_key"
    assert not hmac_verify_func(wrong_key, message, expected_hmac), (
        "Should reject HMAC with wrong key"
    )

    # Test that verification fails with tampered message
    tampered_message = b"Hello, HMAC verification modified!"
    assert not hmac_verify_func(key, tampered_message, expected_hmac), (
        "Should reject HMAC with tampered message"
    )


test_hmac_md5(hmac_md5)
test_hmac_verify(hmac_verify)

# %%
"""
#### HMAC Security Properties

Let's verify that HMAC is resistant to the length extension attack that broke our naive approach:
"""


@report
def test_hmac_security(hmac_md5, length_extension_attack, hmac_verify):
    """Demonstrate that HMAC prevents length extension attacks."""
    secret = b"secret123"
    original_message = b"user=alice&action=view"

    # Generate legitimate HMAC
    original_hmac = hmac_md5(secret, original_message)

    print("HMAC Security Demonstration")
    print("=" * 40)
    print(f"Original message: {original_message}")
    print(f"HMAC:            {original_hmac.hex()}")
    print()

    # Try to perform length extension (this should fail)
    print("Attempting length extension attack on HMAC...")

    # The attack that worked on naive MAC won't work here because:
    # 1. The output is Hash(outer_key || Hash(inner_key || message))
    # 2. Even if you could extend the inner hash, you'd need to know outer_key
    # 3. The outer hash prevents direct extension of the result

    malicious_data = b"&action=admin"

    # Try the same attack as before (it will fail)
    try:
        forged_message, forged_tag = length_extension_attack(
            original_message, original_hmac, len(secret), malicious_data
        )

        # Check if the forged HMAC is valid
        is_valid = hmac_verify(secret, forged_message, forged_tag)
        print(
            f"Length extension attack on HMAC: {'FAILED ✅' if not is_valid else 'SUCCEEDED ✗'}"
        )

    except Exception as e:
        print(f"Length extension attack failed with error: {e}")


test_hmac_security(hmac_md5, length_extension_attack, hmac_verify)

# %%
"""
### Exercise 1.4: Secure Password Storage

Now that you understand how hash functions work, let's explore one of their most critical applications: storing passwords securely. 

> **Difficulty**: 🔴🔴⚪⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~20 minutes on this exercise.

Password storage is a fundamental security challenge that every application faces. Poor password storage has led to massive breaches affecting millions of users:
- **LinkedIn (2012)**: 6.5 million unsalted SHA-1 hashes leaked, most cracked within days
- **Adobe (2013)**: 150 million passwords stored with weak encryption, many cracked
- **Ashley Madison (2015)**: 30 million user accounts leaked; passwords were hashed with bcrypt, but some older accounts used MD5

In this section, you'll learn how password storage evolved from terrible practices to modern secure approaches.

#### The Evolution of Password Storage

**1. Plaintext Storage (Never Do This!)**

The most naive approach is storing passwords as plaintext. This is catastrophic because:
- Any database breach immediately exposes all passwords
- Insiders (employees, contractors) can see user passwords; misusing them is trivial and hard to detect

**2. Basic Hashing (Still Inadequate)**

The next evolution was to hash passwords:
```python
stored_password = hash(password)
```

This seems better - passwords aren't immediately visible. But it's still vulnerable to:
- **Rainbow tables**: Pre-computed hash lookups for common passwords
- **Dictionary attacks**: Hashing common passwords and comparing
- **Identical passwords have identical hashes**: If two users have the same password, it's obvious

**3. Salted Hashing (Better, But Not Enough)**

Adding salt prevents rainbow table attacks:
```python
stored_password = hash(password + salt)
```

There are two approaches:
- **Static salt** (same for all users): Prevents generic rainbow tables but a single brute-force pass can still crack all passwords
- **Per-user salt** (unique for each user): Forces attackers to crack each password individually

**4. Slow Hashing Algorithms (Modern Best Practice)**

The fundamental problem with MD5/SHA-256 for passwords is they're TOO FAST. Modern GPUs can compute billions of hashes per second.

Special password hashing algorithms are designed to be slow:
- **bcrypt**: Adjustable cost factor, typical setting makes it ~1 million times slower than MD5
- **Argon2**: The current gold standard, memory-hard to resist GPU/ASIC attacks

<details>
<summary>Vocabulary: Password Security Terms</summary>

- **Rainbow table**: Pre-computed hash lookups for common passwords
- **Salt**: Random data added to passwords before hashing to prevent rainbow table attacks
- **Dictionary attack**: Systematically testing common passwords
- **Brute force**: Trying all possible password combinations
- **Hash rate**: How many hash operations can be performed per second
- **GPU/ASIC**: Specialized hardware for fast parallel computation
- **Cost factor**: Parameter that controls how slow a password hashing algorithm is
- **Pepper**: Secret added to passwords in a way similar to salt which is (unlike salt) not stored in a separate secret storate rather than alongside a password hash

</details>

### Interactive Exercise: Understanding Password Cracking Economics

Open [hash-crack-cost.html](./resources/hash-crack-cost.html) in your browser and play with the configuration, then answer the questions below.

<details>
<summary>Question 1: Why does the tool show different costs for "Unsalted", "Static salt", and "Per-user salt"?</summary>

With unsalted or static salt hashes, an attacker can test each password guess against ALL hashes simultaneously. For example, computing MD5("password123") once tells you if ANY of the 1000 users has that password.

With per-user salts, each password must be attacked individually. 

The values for unsalted and static salt options is the same because we are assuming a brute-force attack. The values would be different if we assumed a rainbow table attack.
</details>

<details>
<summary>Question 2: Change the algorithm from SHA-256 to Argon2. Why is the hash rate so dramatically different (2 × 10¹¹ vs 6,400 hashes/second)?</summary>

Fast hash functions like MD5 and SHA-256 were designed for speed - they need to quickly verify file integrity or digital signatures. A modern GPU can compute over a trillion MD5 hashes per second!

Password hashing algorithms like Argon2 are intentionally slow and memory-hard:
- **Slow**: Each hash takes significant time (milliseconds vs nanoseconds)
- **Memory-hard**: Requires large amounts of RAM, making GPU/ASIC attacks expensive
- **Configurable**: You can adjust the cost as hardware improves

The 160 million times slowdown (1.04×10¹² ÷ 6,400) makes password cracking economically infeasible for most attackers.
</details>

<details>
<summary>Question 3: [SHA-256](https://en.wikipedia.org/wiki/SHA-2) hash function is widely used in asymmetric cryptography and considered safe. Why is it not safe for hashing passwords then?</summary>
SHA-256 is not safe for hashing passwords primarily because of the vastly different nature of the inputs in password hashing versus its use in asymmetric cryptography.

In asymmetric cryptography, SHA-256 typically hashes large, high-entropy inputs such as public keys, digital messages, or file contents. These inputs are often unpredictable and infeasible to brute-force. The role of the hash function here is to ensure integrity and collision resistance, which SHA-256 provides effectively.

However, in the context of password hashing, the inputs (i.e., passwords) are usually short, low-entropy, and highly guessable. 
</details>
"""

"""
## 2️⃣ RSA Public Key Cryptography

RSA (Rivest-Shamir-Adleman) is a public-key cryptosystem that revolutionized cryptography by enabling secure communication without requiring parties to share a secret key beforehand.
The algorithm relies on the mathematical difficulty of factoring large composite numbers, specifically the product of two large prime numbers.
In RSA, each user has a key pair: a public key (n, e) that can be freely shared, and a private key (n, d) that must be kept secret.
To encrypt a message, the sender converts it to a number m and computes $c = m^e \mod n$ using the recipient's public key.
The recipient then decrypts by computing $m = c^d \mod n$ using their private key.
The security stems from the fact that while it's easy to multiply two large primes together, it's computationally infeasible to factor their product back into the original primes, making it practically impossible to derive the private key from the public key.

Digital signatures with RSA work in reverse to encryption, providing authentication and non-repudiation rather than confidentiality.
To sign a message, the signer first creates a hash of the message using a cryptographic hash function, then "encrypts" this hash with their private key: signature = hash^d mod n.
Anyone can verify the signature by "decrypting" it with the signer's public key (hash' = signature^e mod n) and comparing the result to a fresh hash of the message.
If they match, it proves the signature was created by the holder of the private key and that the message hasn't been altered.
RSA remains widely used in various applications including HTTPS/TLS certificates, email encryption (PGP/GPG), and software signing.
However, RSA requires relatively large key sizes (2048 bits or more) for modern security standards, making it slower than elliptic curve alternatives for equivalent security levels, which is why many systems now use RSA primarily for signatures and key exchange rather than bulk encryption.

### Why RSA Matters

- **Asymmetric cryptography**: Enables secure communication without pre-shared secrets
- **Digital signatures**: Provides authentication and non-repudiation
- **Foundation of PKI**: Used in TLS/SSL certificates, email encryption, code signing
- **Mathematical elegance**: Based on the difficulty of factoring large numbers

### Key Properties of Secure RSA

1. **Large primes**: p and q should be hundreds of digits long (2048+ bits total)
2. **Proper padding**: Never encrypt raw data (use OAEP for encryption, PSS for signatures)
3. **Secure random numbers**: Critical for prime generation and padding
4. **Side-channel resistance**: Constant-time operations to prevent timing attacks
5. **Key management**: Private keys must be protected; public keys must be authenticated

<details>
<summary>Vocabulary: RSA Terms</summary>

- **Public key**: (n, e) - the modulus and public exponent, can be shared freely
- **Private key**: (n, d) - the modulus and private exponent, must be kept secret
- **Modulus (n)**: Product of two primes p × q
- **Euler's totient φ(n)**: (p-1)(q-1) - count of integers coprime to n
- **Modular exponentiation**: Computing a^b mod n efficiently
- **Textbook RSA**: RSA without padding (insecure!)
- **OAEP/PSS**: Padding schemes that make RSA secure

</details>
"""

# %%
"""
### Helper Functions

These functions are provided for you to use in your implementation - just copy then into your solution file.
"""

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
"""
### Exercise 2.1: RSA Key Generation

> **Difficulty**: 🔴🔴🔴⚪⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~20 minutes on this exercise.

Now we'll generate RSA key pairs. The process is:

1. Generate two distinct primes p and q
2. Compute n = p × q (the modulus)
3. Compute φ(n) = (p-1)(q-1) (Euler's totient)
4. Choose public exponent e (typically 65537)
5. Compute private exponent d ≡ e⁻¹ (mod φ(n))

The security comes from the fact that knowing n doesn't let you compute φ(n) without factoring n into p and q.

<details>
<summary>Vocabulary: Key Generation Terms</summary>

- **Modulus (n)**: Public value that's hard to factor
- **Totient φ(n)**: Number of integers coprime to n
- **Public exponent (e)**: Usually 65537 (2¹⁶ + 1) for efficiency
- **Private exponent (d)**: Modular multiplicative inverse of e
- **Coprime**: Two numbers with no common factors except 1
- **Modular inverse**: d such that e × d ≡ 1 (mod φ(n))

</details>

Implement the `generate_keys` function that creates an RSA key pair.
"""


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
    if "SOLUTION":
        rng = random.Random()
        half = bits // 2
        p = get_prime(half, rng)
        q = get_prime(half, rng)
        while p == q:
            q = get_prime(half, rng)

        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        if phi % e == 0:
            # choose smaller exponent
            e = 3
            while phi % e == 0:
                e += 2
        d = pow(e, -1, phi)
        return (n, e), (n, d)
    else:
        # TODO: Implement key generation
        #    - Generate p and q (bits//2 each)
        #    - Ensure p ≠ q
        #    - Compute n and φ(n)
        #    - Choose e (check if coprime with φ)
        #    - Compute d using pow(e, -1, phi)
        pass


@report
def test_generate_keys(generate_keys):
    """Test RSA key generation."""
    print("Testing RSA key generation...")

    # Test 1: Basic key generation
    public, private = generate_keys(16)
    n_pub, e = public
    n_priv, d = private

    print(f"Public key: n={n_pub}, e={e}")
    print(f"Private key: n={n_priv}, d={d}")

    assert n_pub == n_priv, "Modulus should be same in both keys"
    assert e != d, "Public and private exponents should differ"

    # Test 2: Verify key relationship
    # For any message m < n: m^(e×d) ≡ m (mod n)
    test_msg = 42
    encrypted = pow(test_msg, e, n_pub)
    decrypted = pow(encrypted, d, n_priv)
    assert decrypted == test_msg, "Key relationship e×d ≡ 1 (mod φ(n)) failed"

    # Test 3: Generate multiple keys
    keys2 = generate_keys(16)
    assert keys2[0][0] != n_pub, "Should generate different moduli"

    # Test 4: Larger keys
    public_big, private_big = generate_keys(32)
    n_big = public_big[0]
    assert n_big.bit_length() >= 31, "32-bit key should have ~32-bit modulus"

    print("✓ Key generation tests passed!\n" + "=" * 60)


test_generate_keys(generate_keys)

# %%
"""
### Exercise 2.2: RSA Encryption and Decryption

> **Difficulty**: 🔴🔴⚪⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~15 minutes on this exercise.

RSA encryption and decryption use modular exponentiation:
- Encryption: c = m^e mod n (using public key)
- Decryption: m = c^d mod n (using private key)

This works because:
- e × d ≡ 1 (mod φ(n))
- By Euler's theorem: m^(e×d) ≡ m (mod n)

We'll implement a toy version of RSA that encrypts one byte at a time. Real RSA uses padding schemes like OAEP.

<details>
<summary>Vocabulary: Encryption Terms</summary>

- **Plaintext (m)**: Original message
- **Ciphertext (c)**: Encrypted message
- **Modular exponentiation**: Computing a^b mod n efficiently
- **Malleability**: Property where ciphertexts can be manipulated
- **Homomorphic**: RSA is multiplicatively homomorphic

</details>

Implement the `encrypt` and `decrypt` functions.
"""


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
    if "SOLUTION":
        n, e = public_key
        return [pow(b, e, n) for b in message.encode("utf-8")]
    else:
        # TODO: Implement encryption
        #    - Extract n and e from public_key
        #    - Convert message to bytes with .encode("utf-8")
        #    - Encrypt each byte with pow(byte, e, n)
        #    - Return list of encrypted values
        pass


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
    if "SOLUTION":
        n, d = private_key
        decrypted_bytes = bytes(pow(c, d, n) for c in ciphertext)
        return decrypted_bytes.decode("utf-8")
    else:
        # TODO: Implement decryption
        #    - Extract n and d from private_key
        #    - Decrypt each value with pow(c, d, n)
        #    - Convert to bytes and decode UTF-8
        pass


"""
<details>
<summary>Hint 1: Encryption</summary>

```python
n, e = public_key
encrypted = []
for byte in message.encode("utf-8"):
    encrypted.append(pow(byte, e, n))
return encrypted
```

Or more concisely with a list comprehension.
</details>

<details>
<summary>Hint 2: Decryption</summary>

```python
n, d = private_key
decrypted = []
for c in ciphertext:
    decrypted.append(pow(c, d, n))
return bytes(decrypted).decode("utf-8")
```
</details>
"""


@report
def test_encryption(encrypt, decrypt, generate_keys):
    """Test RSA encryption and decryption."""
    print("Testing RSA encryption/decryption...")

    # Generate test keys
    public, private = generate_keys(16)

    # Test 1: Basic encryption/decryption
    message = "Hello, RSA!"
    ciphertext = encrypt(public, message)
    print(f"Message: {message}")
    print(f"Ciphertext: {ciphertext[:5]}... (first 5 values)")

    assert ciphertext != message, "Ciphertext should not equal plaintext"

    decrypted = decrypt(private, ciphertext)
    assert decrypted == message, f"Decryption failed: got '{decrypted}'"
    print(f"Decrypted: {decrypted}")

    # Test 2: Different messages
    msg2 = "Testing 123 🔐"
    ct2 = encrypt(public, msg2)
    assert ct2 != ciphertext, "Different messages should have different ciphertexts"
    assert decrypt(private, ct2) == msg2, "Should handle Unicode"

    # Test 3: Empty message
    empty_ct = encrypt(public, "")
    assert empty_ct == [], "Empty message should produce empty ciphertext"
    assert decrypt(private, empty_ct) == "", "Should handle empty message"

    # Test 4: Wrong key fails
    public2, private2 = generate_keys(16)
    try:
        wrong = decrypt(private2, ciphertext)
        if wrong == message:
            assert False, "Different keys shouldn't decrypt correctly"
    except:
        pass  # Decryption with wrong key may fail

    print("✓ Encryption/decryption tests passed!\n" + "=" * 60)


test_encryption(encrypt_rsa, decrypt_rsa, generate_keys)

# %%
"""
### Exercise 2.3: RSA Digital Signatures

> **Difficulty**: 🔴🔴🔴⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~20 minutes on this exercise.

RSA can also create digital signatures. The operations are "reversed" compared to encryption:
- Signing: s = m^d mod n (using PRIVATE key)
- Verification: m = s^e mod n (using PUBLIC key)

This provides:
- **Authentication**: Only the private key holder can create valid signatures
- **Non-repudiation**: The signer cannot deny creating the signature
- **Integrity**: Any change to the message invalidates the signature

<details>
<summary>Vocabulary: Signature Terms</summary>

- **Digital signature**: Mathematical proof of authenticity
- **Signing**: Creating a signature with private key
- **Verification**: Checking signature with public key
- **Non-repudiation**: Signer cannot deny signing
- **Hash-and-sign**: Real signatures hash the message first
- **Blind signatures**: Signing without seeing the message

</details>

Implement the `sign` and `verify` functions.
"""


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
    if "SOLUTION":
        n, d = private_key
        return [pow(b, d, n) for b in message.encode("utf-8")]
    else:
        # TODO: Implement signing
        #    - Extract n and d from private_key
        #    - Convert message to bytes
        #    - Sign each byte with pow(byte, d, n)
        pass


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
    if "SOLUTION":
        n, e = public_key
        recovered_ints = [pow(s, e, n) for s in signature]
        if any(x > 255 for x in recovered_ints):
            return False
        recovered = bytes(recovered_ints)
        try:
            return recovered.decode("utf-8") == message
        except UnicodeDecodeError:
            return False
    else:
        # TODO: Implement verification
        #    - Extract n and e from public_key
        #    - Recover each byte with pow(s, e, n)
        #    - Check if recovered bytes match original message
        #    - Return False for any errors
        pass


"""
<details>
<summary>Hint 1: Signing process</summary>

Signing is like "encrypting with the private key":
```python
n, d = private_key
signature = []
for byte in message.encode("utf-8"):
    signature.append(pow(byte, d, n))
```
</details>

<details>
<summary>Hint 2: Verification process</summary>

Verify by "decrypting with the public key" and comparing:
```python
n, e = public_key
recovered = []
for s in signature:
    recovered.append(pow(s, e, n))
# Check if recovered matches original message
```
</details>

<details>
<summary>Hint 3: Error handling</summary>

A valid signature should:
- Recover to valid byte values (0-255)
- Decode as valid UTF-8
- Match the original message exactly

Return False if any of these fail.
</details>
"""


@report
def test_signatures(sign, verify, generate_keys):
    """Test RSA signatures."""
    print("Testing RSA signatures...")

    # Generate test keys
    public, private = generate_keys(16)

    # Test 1: Valid signature
    message = "I agree to the terms"
    signature = sign(private, message)
    print(f"Message: {message}")
    print(f"Signature: {signature[:5]}... (first 5 values)")

    assert verify(public, message, signature), "Valid signature should verify"
    print("✓ Signature verified")

    # Test 2: Modified message
    tampered = "I agree to the termz"  # Changed 's' to 'z'
    assert not verify(public, tampered, signature), "Modified message should fail"
    print("✓ Tampered message rejected")

    # Test 3: Modified signature
    bad_sig = signature.copy()
    bad_sig[0] += 1
    assert not verify(public, message, bad_sig), "Modified signature should fail"
    print("✓ Tampered signature rejected")

    # Test 4: Wrong key
    public2, private2 = generate_keys(16)
    sig2 = sign(private2, message)
    assert not verify(public, message, sig2), "Wrong key signature should fail"
    print("✓ Wrong key signature rejected")

    # Test 5: Signature uniqueness
    msg1 = "Hello"
    msg2 = "World"
    sig1 = sign(private, msg1)
    sig2 = sign(private, msg2)
    assert sig1 != sig2, "Different messages should have different signatures"

    print("✓ All signature tests passed!\n" + "=" * 60)


test_signatures(sign, verify, generate_keys)

# %%
"""
### Summary and Security Considerations

#### Vulnerabilities of Textbook RSA and Their Mitigations

**1. Deterministic Encryption**
- **Vulnerability**: Same plaintext always produces identical ciphertext
- **Why this matters**: Attackers can perform frequency analysis on encrypted communications, build dictionaries of common encrypted values (e.g., "Yes"→ciphertext₁, "No"→ciphertext₂), and recognize patterns in encrypted data
- **Mitigations**: RSA-OAEP adds randomized padding before encryption, ensuring the same message encrypts to different ciphertexts each time, providing semantic security

**2. Malleability** 
- **Vulnerability**: RSA is multiplicatively homomorphic: E(m₁) × E(m₂) = E(m₁ × m₂)
- **Why this matters**: Attackers can manipulate encrypted values without decrypting them - multiply a salary by E(2) to double it, or multiply by E(0) to zero it out, all while maintaining valid encryption
- **Mitigations**: RSA-OAEP includes integrity checks and structured padding that makes malleated ciphertexts decrypt to invalid padding, preventing manipulation attacks

**3. Small Message Space**
- **Vulnerability**: Single bytes have only 256 possible values  
- **Why this matters**: Attackers can pre-compute encryptions of all possible byte values, then instantly "decrypt" any ciphertext by table lookup - no key needed
- **Mitigations**: RSA-OAEP's randomized padding exponentially expands the effective message space, making brute force computationally infeasible

**4. No Integrity Protection**
- **Vulnerability**: Modified ciphertext decrypts to garbage without detection
- **Why this matters**: Attackers can corrupt data in transit, causing applications to process malicious input, crash systems, or leak information through error messages
- **Mitigations**: RSA-OAEP includes built-in integrity verification - corrupted ciphertexts are detected and rejected during decryption

**5. Small Key Sizes**
- **Vulnerability**: Our 16-bit keys can be factored in microseconds
- **Why this matters**: Once an attacker factors n = p × q, they can compute the private key and decrypt all messages or forge signatures
- **Mitigations**: Use ≥2048-bit keys (current standard) or ≥3072-bit keys (future-proof against quantum computers); factoring such numbers requires more computational power than exists

#### Modern RSA Implementation Security

**RSA-OAEP for Encryption**: Provides semantic security, prevents chosen ciphertext attacks, includes integrity verification

**RSA-PSS for Signatures**: Signs message hashes (not raw messages), adds randomized salt for security, provides strong unforgeability guarantees, much more efficient for long messages  

**Side-Channel Protection**: Constant-time operations prevent timing attacks, blinding prevents power analysis, secure random number generation, protection against fault injection attacks

"""

# %%
"""
## 3️⃣ Padding Oracle Attacks
Now you'll implement one of the most elegant attacks in cryptography: the padding oracle attack. This attack demonstrates how a tiny information leak (whether padding is valid) can completely compromise encryption.

It has been used to break popular frameworks and protocols. E.g., this attack was used to completely break ASP.NET's authentication cookies in 2010, allowing attackers to forge admin credentials. 
In 2015, the POODLE attack prompted final replacement of SSL with TLS.

### Why Learn about Padding Oracles Attacks?
<!-- FIXME: highlight this later where they can connect it with the exercises  -->

Padding oracle attacks demonstrate several critical security principles:

1. **Small leaks break cryptography**: Even revealing whether padding is valid breaks semantic security
2. **Implementation details matter**: Theoretically secure algorithms can be broken by poor implementation
3. **Side channels are everywhere**: Error messages, timing differences, and behavior changes leak information
4. **Defense in depth**: Encryption alone isn't enough - you need authentication too

Understanding this attack helps you **recognize similar vulnerabilities in AI systems**, where models might leak information through timing, error messages, or behavior differences (e.g., help an AI system recognize whether it's in a test or production environment).

<details>
<summary>Vocabulary: Padding Oracle Terms</summary>

- **Oracle**: A system that answers queries about secret information through observable differences in behavior (e.g., timing, error messages, etc.), without directly revealing the secret itself. 
- **Ciphertext**: The encrypted data produced by an encryption algorithm.
- **CBC Mode** (Cipher Block Chaining): Block cipher mode where each plaintext block is XORed with the previous ciphertext block before encryption, creating a dependency chain. 
- **Initialization Vector (IV)**: A random value used to initialize the first block of ciphertext in CBC mode (i.e., the first block of ciphertext is XORed with the IV).
- **Side channel**: An unintended communication channel that leaks information through observable physical or behavioral characteristics of a system's implementation (e.g., time, power consumption, cache behavior, error messages,...)

</details>
<br>
"""

# %%
"""
### Exercise 3.1: PKCS#7 Padding

Block ciphers (e.g., AES) only encrypt fixed-size blocks, but real messages have arbitrary lengths. Without padding, the cipher literally doesn't know what to do with incomplete blocks. PKCS#7 padding ensures that plaintext is a multiple of the block size.

#### Exercise - implement add_pkcs7_padding

> **Difficulty**: 🔴⚪⚪⚪⚪
> **Importance**: 🔵🔵⚪⚪⚪

Implement the `add_pkcs7_padding` function that adds PKCS#7 padding to a message.

The padding scheme is:
- If you need N bytes of padding, append N copies of the byte value N
- Add padding even if the plaintext is already a multiple of the block size

> Examples for 16-byte blocks:
> - `b"YELLOW SUBMARINE"` → Already 16 bytes, add 16 bytes of `\x10`
> - `b"HIJACKERS"` → 9 bytes, add 7 bytes of `\x07`
> - `b"A"` → 1 byte, add 15 bytes of `\x0f`

Another example:<br>
<img src="./resources/pkcs-padding.png" alt="PKCS#7 padding" width="500"/><br>
<sub>Source: [aon.com](https://cyber.aon.com/aon_cyber_labs/automated-padding-oracle-attacks-with-padbuster/)</sub>

This design makes padding removal unambiguous. You read the last byte, and you know exactly how many padding bytes to remove.
"""


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
    if "SOLUTION":
        padding_length = block_size - (len(plaintext) % block_size)
        padding = bytes([padding_length] * padding_length)
        return plaintext + padding
    else:
        # TODO: Implement PKCS#7 padding according to the spec above
        pass


@report
def test_add_pkcs7_padding(add_pkcs7_padding_func):
    # Test 1: Empty input
    result = add_pkcs7_padding_func(b"")
    assert result == b"\x10" * 16, f"Empty input failed: {result.hex()}"

    # Test 2: Input shorter than block
    result = add_pkcs7_padding_func(b"HIJACKERS")
    assert result == b"HIJACKERS" + b"\x07" * 7, f"Short input failed: {result.hex()}"

    # Test 3: Input exactly one block
    result = add_pkcs7_padding_func(b"YELLOW SUBMARINE")
    assert result == b"YELLOW SUBMARINE" + b"\x10" * 16, (
        f"Full block failed: {result.hex()}"
    )

    # Test 4: Multi-block input
    result = add_pkcs7_padding_func(b"A" * 17)
    assert result == b"A" * 17 + b"\x0f" * 15, f"Multi-block failed: {result.hex()}"


test_add_pkcs7_padding(add_pkcs7_padding)

# %%
"""
#### Exercise - implement remove_pkcs7_padding
Removing padding requires validation to prevent attacks. The function should:
1. Check that the last byte is a valid padding value (1-16 for 16-byte blocks)
2. Verify that all padding bytes have the correct value

Don't forget to consider other edge cases as well.

> **Difficulty**: 🔴⚪⚪⚪⚪
> **Importance**: 🔵🔵⚪⚪⚪
"""


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
    if "SOLUTION":
        if len(padded_text) == 0:
            raise InvalidPaddingError("Empty input")

        padding_length = padded_text[-1]

        if padding_length < 1 or padding_length > block_size:
            raise InvalidPaddingError(f"Invalid padding length: {padding_length}")

        if len(padded_text) < padding_length:
            raise InvalidPaddingError("Padding length exceeds data length")

        # Check all padding bytes
        for i in range(padding_length):
            if padded_text[-(i + 1)] != padding_length:
                raise InvalidPaddingError("Inconsistent padding bytes")

        return padded_text[:-padding_length]
    else:
        # TODO: Implement PKCS#7 unpadding with validation
        pass


@report
def test_remove_pkcs7_padding(remove_pkcs7_padding_func, InvalidPaddingError):
    """Test PKCS#7 unpadding with validation."""
    # Test 1: Valid single-byte padding
    ciphertext = b"HELLO" + b"\x0b" * 11
    result = remove_pkcs7_padding_func(ciphertext)
    assert result == b"HELLO", f"Removing padding from {ciphertext} failed: {result}"

    # Test 2: Valid full-block padding
    ciphertext = b"YELLOW SUBMARINE" + b"\x10" * 16
    result = remove_pkcs7_padding_func(ciphertext)
    assert result == b"YELLOW SUBMARINE", (
        f"Removing padding from {ciphertext} failed: {result}"
    )

    # Test 3: Invalid padding length
    try:
        ciphertext = b"HELLO" + b"\x00" * 11
        remove_pkcs7_padding_func(ciphertext)
        assert False, (
            f"Removing padding from {ciphertext} should have raised InvalidPaddingError for zero padding"
        )
    except InvalidPaddingError:
        pass

    # Test 4: Inconsistent padding bytes
    try:
        ciphertext = b"HELLO" + b"\x0b" * 10 + b"\x0a"
        remove_pkcs7_padding_func(ciphertext)
        assert False, (
            f"Removing padding from {ciphertext} should have raised InvalidPaddingError for inconsistent padding"
        )
    except InvalidPaddingError:
        pass

    # Test 5: Padding length exceeds data length
    try:
        ciphertext = b"\x10\x10\x10\x10"
        remove_pkcs7_padding_func(ciphertext)
        assert False, (
            f"Removing padding from {ciphertext} should have raised InvalidPaddingError for padding length exceeding data length"
        )
    except InvalidPaddingError as e:
        pass

    # Test 6: Empty input
    try:
        remove_pkcs7_padding_func(b"")
        assert False, "Should have raised InvalidPaddingError for empty input"
    except InvalidPaddingError:
        pass


test_remove_pkcs7_padding(remove_pkcs7_padding, InvalidPaddingError)

# %%
"""
### Exercise 3.2: CBC Mode Implementation

Now let's implement CBC (Cipher Block Chaining) mode encryption and decryption. CBC mode:
1. XORs each plaintext block with the previous ciphertext block before encryption
2. Uses an Initialization Vector (IV) for the first block. The IV must be random but doesn't need to be secret.
3. Requires padding for messages that aren't multiples of the block size

**Why block chaining?** It ensures that even identical plaintext blocks produce different ciphertext blocks, preventing pattern analysis. Each ciphertext block depends on all previous plaintext blocks, and flipping a bit in one ciphertext block affects all subsequent blocks.

The formula for encryption and decryption (assuming AES as the underlying block cipher) are:

- **Encryption:** `C[i] = AES(P[i] ⊕ C[i-1])` 

- **Decryption:** `P[i] = AES_decrypt(C[i]) ⊕ C[i-1]`

where
- `C[i]` is the `i`th ciphertext block,
- `C[0] = IV`
- `P[i]` is the `i`th plaintext block
- `⊕` is the XOR operation


Visually, encryption looks like this (where E<sub>k</sub> stands for the encryption algorithm):<br>
<img src="./resources/cbc.png" alt="CBC Encryption" width="500"/><br>
<sub>Source: [Alan Kaminski](https://www.cs.rit.edu/~ark/fall2012/482/module05/CbcEncrypt.png)</sub>


#### Exercise - implement cbc_encrypt

> **Difficulty**: 🔴🔴⚪⚪⚪
> **Importance**: 🔵🔵🔵🔵⚪

Implement encryption using the formula above and the provided functions `xor_bytes()`, and `single_block_aes_encrypt()`.

"""


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
    if "SOLUTION":
        # Add padding
        padded_plaintext = add_pkcs7_padding(plaintext)

        # Encrypt blocks
        ciphertext = b""
        previous_block = iv

        for i in range(0, len(padded_plaintext), 16):
            block = padded_plaintext[i : i + 16]
            xored = xor_bytes(block, previous_block)
            encrypted_block = single_block_aes_encrypt(xored, key)
            ciphertext += encrypted_block
            previous_block = encrypted_block

        return ciphertext
    else:
        # TODO: Implement CBC encryption
        pass


@report
def test_cbc_encrypt(cbc_encrypt_func):
    key = b"YELLOW SUBMARINE"
    iv = b"\x0b" * 16  # this should be random, but we'll use a fixed value for testing

    # Test 1: Single block
    plaintext = b"HELLO WORLD!!!!!"  # 16 bytes
    ciphertext = cbc_encrypt_func(plaintext, key, iv)
    assert len(ciphertext) == 32, (
        f"Wrong length of ciphertext for plaintext {plaintext}: {len(ciphertext)}"
    )

    # Test: Block length not aligned with block size
    plaintext = b"HELLO WORLD"  # 11 bytes
    ciphertext = cbc_encrypt_func(plaintext, key, iv)
    assert len(ciphertext) == 16, (
        f"Wrong length of ciphertext for plaintext {plaintext}: {len(ciphertext)}"
    )

    # Test 2: Multiple blocks
    plaintext = b"A" * 33
    ciphertext = cbc_encrypt_func(plaintext, key, iv)
    assert len(ciphertext) == 48, f"Wrong length for multi-block: {len(ciphertext)}"

    # Test 3: Ensure different blocks produce different ciphertext (due to chaining)
    plaintext = b"A" * 16
    ciphertext = cbc_encrypt_func(plaintext, key, iv)
    # In ECB mode, identical blocks would produce identical ciphertext
    # In CBC, they should differ due to chaining
    block1 = ciphertext[:16]
    block2 = ciphertext[16:32]
    assert block1 != block2, (
        "Different blocks should produce different ciphertext (input: {plaintext})"
    )


test_cbc_encrypt(cbc_encrypt)

# %%
"""
#### Exercise - implement cbc_decrypt

Now implement CBC decryption using the provided `single_block_aes_decrypt()` function. The process should be basically the inverse of the encryption process. Use the formula and hints from the previous exercise.

> **Difficulty**: 🔴🔴🔴⚪⚪
> **Importance**: 🔵🔵🔵🔵⚪

<!-- FIXME: reported by participant:  On CBC Encrypt (3.2), the excercise LIES to you. The plaintext is not padded (as the comments seem to imply will come in already padded). Do not fall for this! -->
"""


# %%
def single_block_aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    assert len(ciphertext) == 16, "Ciphertext must be 16 bytes"
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)


def cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt ciphertext using AES in CBC mode.

    Args:
        ciphertext: The encrypted message
        key: AES key (16, 24, or 32 bytes)
        iv: Initialization vector (16 bytes)

    Returns:
        Decrypted plaintext with padding removed

    Raises:
        InvalidPaddingError: If padding is invalid
    """
    if "SOLUTION":
        plaintext = b""
        previous_block = iv

        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i : i + 16]
            decrypted = single_block_aes_decrypt(block, key)
            plaintext_block = xor_bytes(decrypted, previous_block)
            plaintext += plaintext_block
            previous_block = block

        return remove_pkcs7_padding(plaintext)
    else:
        # TODO: Implement CBC decryption
        pass


@report
def test_cbc_decrypt(cbc_decrypt_func, cbc_encrypt_func, InvalidPaddingError):
    key = b"YELLOW SUBMARINE"
    iv = b"\x0b" * 16  # this should be random, but we'll use a fixed value for testing

    # Test 1: Known ciphertext
    # First create a properly encrypted message
    cipher = AES.new(
        key, AES.MODE_CBC, iv
    )  # test this with a library implementation of CBC
    plaintext = b"HELLO WORLD!"
    padded = plaintext + b"\x04" * 4  # Proper padding
    ciphertext = cipher.encrypt(padded)

    result = cbc_decrypt_func(ciphertext, key, iv)
    assert result == plaintext, f"Decryption failed: got {result}, expected {plaintext}"

    # Test 2: Invalid padding should raise error
    bad_ciphertext = ciphertext[:-1] + b"\x00"  # Corrupt last byte
    try:
        cbc_decrypt_func(bad_ciphertext, key, iv)
        assert False, (
            "Should have raised InvalidPaddingError for ciphertext {bad_ciphertext}"
        )
    except InvalidPaddingError:
        pass

    # Test 3: Ciphertext not aligned with 16-byte blocks should raise error
    misaligned_ciphertext = ciphertext[
        :-5
    ]  # Remove 5 bytes to make it not divisible by 16
    try:
        cbc_decrypt_func(misaligned_ciphertext, key, iv)
        assert False, (
            "Should have raised a padding error for misaligned ciphertext {misaligned_ciphertext}"
        )
    except Exception:
        pass  # Any exception is acceptable for misaligned input

    # Test 4: Round-trip test - encrypt then decrypt should recover original plaintext
    original_plaintext = b"The quick brown fox jumps over the lazy dog"
    encrypted = cbc_encrypt_func(original_plaintext, key, iv)
    decrypted = cbc_decrypt_func(encrypted, key, iv)
    assert decrypted == original_plaintext, (
        f"Decryption of plaintext {original_plaintext} encrypted with cbc_encrypt() failed: got {decrypted}"
    )

    # Test 5: Round-trip with different plaintext lengths
    for length in [1, 15, 16, 17, 32, 33]:
        test_plaintext = b"X" * length
        encrypted = cbc_encrypt_func(test_plaintext, key, iv)
        decrypted = cbc_decrypt_func(encrypted, key, iv)
        assert decrypted == test_plaintext, (
            f"Decryption of plaintext {test_plaintext} encrypted with cbc_encrypt() failed: got {decrypted}, expected {test_plaintext}"
        )


test_cbc_decrypt(cbc_decrypt, cbc_encrypt, InvalidPaddingError)

# %%
"""
### Exercise 3.3: The Vulnerable Server and Initialization Vector

Now we'll create a "server" that has a padding oracle vulnerability. Real-world padding oracles can manifest as:
- Explicit error messages ("Invalid padding" vs "Invalid MAC")
- Different HTTP status codes (400 vs 500)
- Timing differences (early return on padding error)
- Behavioral differences (connection drop, log entries, retries, etc.)

Our server will decrypt cookies and return different errors for padding vs other failures.

Let's also take this opportunity to examine how **IV (Initialization Vector) should be handled**:

- IV is typically generated by the encryptor when creating ciphertext.
- IV should be **unpredictable and randomly generated** for each encryption operation
- The IV used for decryption must be the same as the one used for encryption (i.e. is is not secret). The IV is often prepended to the ciphertext to be extracted by the decryptor.


#### Exercise - implement VulnerableServer

> **Difficulty**: 🔴🔴⚪⚪⚪
> **Importance**: 🔵🔵🔵🔵⚪
>
"""


# %%
class VulnerableServer:
    """
    A server vulnerable to padding oracle attacks.
    """

    def __init__(self, key: bytes = None):
        """Initialize with a random AES key."""
        self.key = key or secrets.token_bytes(16)

    def encrypt_cookie(self, cookie_content: dict[str, str]) -> bytes:
        """Encrypt a cookie value."""
        if "SOLUTION":
            plaintext = json.dumps(cookie_content).encode()
            iv = secrets.token_bytes(16)
            ciphertext = cbc_encrypt(plaintext, self.key, iv)
            return iv + ciphertext
        else:
            # TODO: Implement cookie encryption
            # - Serialize cookie_content as a JSON string and encode it as bytes
            # - Use the cbc_encrypt() function you implemented earlier
            # - Don't forget to include the IV in the returned value so that you can decrypt it later!
            pass

    def decrypt_cookie(
        self, cookie: bytes
    ) -> Tuple[Literal[False], str] | Tuple[Literal[True], dict[str, str]]:
        """
        Decrypt and validate a cookie.

        Returns:
            - (True, decrypted_cookie) if decryption succeeds, where decrypted_cookie is parsed as json from plaintext
            - (False, "PADDING_ERROR") if padding is invalid
            - (False, "INVALID_COOKIE") for other errors

        This is the padding oracle - it leaks whether padding is valid!
        """

        if "SOLUTION":
            try:
                if len(cookie) < 32:
                    return False, "INVALID_COOKIE"

                iv = cookie[:16]
                ciphertext = cookie[16:]

                plaintext = cbc_decrypt(ciphertext, self.key, iv)
                return True, json.loads(plaintext)

            except InvalidPaddingError:
                return False, "PADDING_ERROR"
            except Exception as e:
                print("Invalid cookie: ", e)
                return False, "INVALID_COOKIE"
        else:
            # TODO: Implement the vulnerable decryption
            # - Use the cbc_decrypt() function you implemented earlier
            # - Return (False, "PADDING_ERROR") if cbc_decrypt() raises an InvalidPaddingError
            # - Return (False, "INVALID_COOKIE") if any other error is detected, including when the cookie is not valid JSON
            pass


@report
def test_vulnerable_server(VulnerableServer, cbc_encrypt):
    server = VulnerableServer()

    # Test 1: Valid cookie encryption/decryption
    cookie_data = {"admin": "true", "user_email": "bob@example.com"}
    cookie = server.encrypt_cookie(cookie_data)
    assert len(cookie) >= 32, "Cookie too short"

    success, result = server.decrypt_cookie(cookie)
    assert success is True, f"Valid cookie should decrypt successfully, got {result}"
    assert result == cookie_data, (
        f"Decrypted cookie should match original: got {result}, expected {cookie_data}"
    )

    # Test 2: Invalid padding oracle
    bad_cookie = cookie[:-1] + bytes([(cookie[-1] ^ 1)])  # Flip last bit
    success, error = server.decrypt_cookie(bad_cookie)
    assert success is False, "Invalid padding should fail"
    assert error == "PADDING_ERROR", f"Should return PADDING_ERROR, got {error}"

    # Test 3: Too short cookie
    success, error = server.decrypt_cookie(b"short")
    assert success is False, "Short cookie should fail"
    assert error == "INVALID_COOKIE", f"Should return INVALID_COOKIE, got {error}"

    # Test 4: IV is not reused
    same_cookie_data = {"message": "same data"}
    cookie1 = server.encrypt_cookie(same_cookie_data)
    cookie2 = server.encrypt_cookie(same_cookie_data)

    iv1 = cookie1[:16]  # First 16 bytes are the IV
    iv2 = cookie2[:16]  # First 16 bytes are the IV
    assert iv1 != iv2, "IV should not be reused across different messages"

    # Test 5: Invalid JSON
    invalid_cookie = b"invalid_cookie"
    iv = secrets.token_bytes(16)
    ciphertext = iv + cbc_encrypt(invalid_cookie, server.key, iv)
    success, error = server.decrypt_cookie(ciphertext)
    assert success is False, f"Invalid cookie should fail, got {error}"
    assert error == "INVALID_COOKIE", f"Should return INVALID_COOKIE, got {error}"


test_vulnerable_server(VulnerableServer, cbc_encrypt)

# %%
"""

#### Exercise - think about Initialization Vector

> **Difficulty**: 🔴🔴⚪⚪⚪
> **Importance**: 🔵🔵🔵🔵⚪

Before moving on to the attack on our padding oracle, let's think about the implications of using a static or predictable IV.

Think about the following questions before expanding the answers. Can you guess what happens in these situations?

<details style="background-color: #f0f0f0; padding: 10px;">
<summary>Question: <b>What would happen if the IV is static or predictable?</b></summary>

If the IV is predictable (e.g., a counter, timestamp, or fixed value), it enables **chosen-plaintext attacks**. An attacker who can:
1. Predict the next IV to be used
2. Influence some part of the plaintext being encrypted

Can learn information about other parts of the plaintext. 

**Real-world example**: The BEAST attack (2011) exploited predictable IVs in TLS 1.0. In TLS 1.0, the IV for record n+1 was the last ciphertext block of record n, making it predictable. Attackers could:
- Inject chosen plaintexts into the victim's TLS stream (e.g., via JavaScript)
- Use the predictable IV to set up equations that reveal secret data byte-by-byte
- Decrypt session cookies and hijack HTTPS sessions

A static IV (same for all messages) is even worse - it's just a special case of predictable IV where prediction is trivial!

</details>

<br>

<details style="background-color: #f0f0f0; padding: 10px;">
<summary>Question: <b>What would happen if the same IV was reused for multiple messages?</b></summary>

IV reuse breaks the fundamental security property of CBC mode. Here's what happens:

1. First blocks become deterministic: If two messages have the same first plaintext block P and use the same IV, they'll have the same first ciphertext block.

2. Information leakage: Attacker can detect when messages start the same way and identify repeated messages or common prefixes.

3. Enables attacks with known plaintext: If attacker knows one plaintext-ciphertext pair with that IV, they can deduce relationships between other messages using same IV and potentially decrypt parts of other messages.

</details>

"""

# %%
"""
### Exercise 4: The Padding Oracle Attack

Now for the main event! The padding oracle attack works by:
1. Modifying the ciphertext block to be decrypted, starting with the last byte of a block
3. Trying all 256 possible values for the corresponding ciphertext byte in the previous block
4. When we find valid padding, we know the intermediate decryption value
5. XORing with the original ciphertext gives us the plaintext

**The key insight:** In CBC decryption, `P[i] = D(C[i]) ⊕ C[i-1]`. If we can control `C[i-1]` and detect valid padding, we can deduce `D(C[i])`!

That was a high-level overview. Let's dive into the details.

#### Attacking a single block
Let's start with a simplified situation where the message length is less than a single block. 
We assume we have the ciphertext, which is (for the one-block case):

```
IV || C[0]` = `IV || AES(P[0] ⊕ IV)
```

(`||` denotes concatenation.) Our goal is to recover the plaintext `P[0] = AES_decrypt(C[0]) ⊕ IV`. Let's denote `intermediary = AES_decrypt(C[0])` to make this 

```
P[0] = AES_decrypt(C[0]) ⊕ IV = intermediary ⊕ IV
```

We also assume we can query the oracle with arbitrary input - specifically, we can change the IV part of the ciphertext. 
Let's start with IV equal to all zeroes and query the oracle (assuming block size of 8 for simplicity):

<table style="border-collapse: collapse; font-family: Arial, sans-serif; font-size: 12px; margin: 20px;">
        <tr>
            <td colspan="9" style="background-color: #333; color: white; text-align: center; padding: 8px; font-weight: bold;">
                BLOCK 1 of 1
            </td>
        </tr>
        <tr>
            <td style="background-color: #e8f4fd; padding: 8px; font-weight: bold; color: #0066cc;">Encrypted Input</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x3F</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x51</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x96</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x3C</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0xB8</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x9F</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x53</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x37</td>
        </tr>
        <tr>
            <td></td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
        </tr>
        <tr>
            <td colspan="9" style="text-align: center; padding: 8px; font-weight: bold; background-color: #f8f8f8;">
                AES
            </td>
        </tr>
        <tr>
            <td></td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
        </tr>
        <tr>
            <td style="background-color: #f0f0f0; padding: 8px; font-weight: bold;">Intermediary Value</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x39</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x73</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x23</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x22</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x97</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x6a</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x26</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x30</td>
        </tr>
        <tr>
            <td></td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
        </tr>
        <tr>
            <td style="background-color: #e8f4fd; padding: 8px; font-weight: bold; color: #0066cc;">Initialization Vector</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x00</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x00</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x00</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x00</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x00</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x00</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x00</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x00</td>
        </tr>
        <tr>
            <td></td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
        </tr>
        <tr>
            <td style="background-color: #f0f0f0; padding: 8px; font-weight: bold;">Decrypted Value</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x39</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x73</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x23</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x22</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x97</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x6a</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x26</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px; background-color: #ffebee; border: 2px solid #d32f2f;">0x30</td>
        </tr>
        <tr>
            <td colspan="8"></td>
            <td style="text-align: center; color: #d32f2f; font-size: 24px; font-weight: bold;">✗</td>
        </tr>
        <tr>
            <td colspan="8"></td>
            <td style="text-align: center; color: #d32f2f; font-weight: bold; font-size: 10px;">INVALID PADDING</td>
        </tr>
</table>

(Blue rows are known to or controlled by the attacker.) The chances are that the last byte of the decrypted plaintext is not going to be a valid padding byte (0x30 in the example), so the oracle will return a padding error.
However, we can increase the value of IV by one and try again, until we succeed in at most 256 attempts:

<table style="border-collapse: collapse; font-family: Arial, sans-serif; font-size: 12px; margin: 20px;">
        <tr>
            <td colspan="9" style="background-color: #333; color: white; text-align: center; padding: 8px; font-weight: bold;">
                BLOCK 1 of 1
            </td>
        </tr>
        <tr>
            <td style="background-color: #e8f4fd; padding: 8px; font-weight: bold; color: #0066cc;">Encrypted Input</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x3F</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x51</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x96</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x3C</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0xB8</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x9F</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x53</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x37</td>
        </tr>
        <tr>
            <td></td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
        </tr>
        <tr>
            <td colspan="9" style="text-align: center; padding: 8px; font-weight: bold; background-color: #f8f8f8;">
                AES
            </td>
        </tr>
        <tr>
            <td></td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
        </tr>
        <tr>
            <td style="background-color: #f0f0f0; padding: 8px; font-weight: bold;">Intermediary Value</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x39</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x73</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x23</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x22</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x97</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x6a</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x26</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x30</td>
        </tr>
        <tr>
            <td></td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
        </tr>
        <tr>
            <td style="background-color: #e8f4fd; padding: 8px; font-weight: bold; color: #0066cc;">Initialization Vector</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x00</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x00</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x00</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x00</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x00</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x00</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x00</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px; background-color: #fff3cd;">0x31</td>
        </tr>
        <tr>
            <td></td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
        </tr>
        <tr>
            <td style="background-color: #f0f0f0; padding: 8px; font-weight: bold;">Decrypted Value</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x39</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x73</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x23</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x22</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x97</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x6a</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x26</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px; background-color: #e8f5e8; border: 2px solid #4caf50;">0x01</td>
        </tr>
        <tr>
            <td colspan="8"></td>
            <td style="text-align: center; color: #3fb043; font-size: 24px; font-weight: bold;">✓</td>
        </tr>
        <tr>
            <td colspan="8"></td>
            <td style="text-align: center; color: #3fb043; font-weight: bold; font-size: 10px;">VALID</td>
        </tr>
</table>

This gives us signal that the last byte of the plaintext for given IV is 0x01.  
Recall that `P[0] = intermediary ⊕ IV`. Together, this gives us the last byte of intermediary (`intermediary = P[0] ⊕ IV`): 0x01 ⊕ 0x31 = 0x30.

**Now that we've decrypted the last byte of the sample block to be 0x30**, we can move on to the second last byte.

In order to crack the last byte, we brute forced an IV byte that would produce a last decrypted byte value of 0x01 (valid padding). In order to crack the second last one, we need to do the same thing, but this time both bytes must equal 0x02 to be valid padding. We already know that the last intermediary byte is  0x30, we can update the last IV byte directly to 0x30 ⊕ 0x02 = 0x32, and then brute force only the second last byte of IV through its 256 options. Continuing with our example, we'll succeed with 0x24:

<table style="border-collapse: collapse; font-family: Arial, sans-serif; font-size: 12px; margin: 20px;">
        <tr>
            <td colspan="9" style="background-color: #333; color: white; text-align: center; padding: 8px; font-weight: bold;">
                BLOCK 1 of 1
            </td>
        </tr>
        <tr>
            <td style="background-color: #e8f4fd; padding: 8px; font-weight: bold; color: #0066cc;">Encrypted Input</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x3F</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x51</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x96</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x3C</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0xB8</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x9F</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x53</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x37</td>
        </tr>
        <tr>
            <td></td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
        </tr>
        <tr>
            <td colspan="9" style="text-align: center; padding: 8px; font-weight: bold; background-color: #f8f8f8;">
                AES
            </td>
        </tr>
        <tr>
            <td></td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
        </tr>
        <tr>
            <td style="background-color: #f0f0f0; padding: 8px; font-weight: bold;">Intermediary Value</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x39</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x73</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x23</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x22</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x97</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x6a</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x26</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x30</td>
        </tr>
        <tr>
            <td></td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
            <td style="text-align: center; font-size: 20px;">⊕</td>
        </tr>
        <tr>
            <td style="background-color: #e8f4fd; padding: 8px; font-weight: bold; color: #0066cc;">Initialization Vector</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x00</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x00</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x00</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x00</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x00</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x00</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px; background-color: #fff3cd;">0x24</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x32</td>
        </tr>
        <tr>
            <td></td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
            <td style="text-align: center; font-size: 16px;">↓</td>
        </tr>
        <tr>
            <td style="background-color: #f0f0f0; padding: 8px; font-weight: bold;">Decrypted Value</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x39</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x73</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x23</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x22</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x97</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px;">0x6a</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px; background-color: #e8f5e8; border: 2px solid #4caf50;">0x02</td>
            <td style="border: 1px solid #ccc; text-align: center; padding: 8px; background-color: #e8f5e8; border: 2px solid #4caf50;">0x02</td>
        </tr>
        <tr>
            <td colspan="8"></td>
            <td style="text-align: center; color: #3fb043; font-size: 24px; font-weight: bold;">✓</td>
        </tr>
        <tr>
            <td colspan="8"></td>
            <td style="text-align: center; color: #3fb043; font-weight: bold; font-size: 10px;">VALID</td>
        </tr>
</table>

Succeeding with IV byte 0x24 reveals the second last byte of intermediary to be 0x02 ⊕ 0x24 = **0x26**!

Rinse and repeat until we decode the whole block in at most 256 * _block size_ queries to the oracle. Not bad!

**One last step remaining:** we have recovered only the intermediary value (0x3973232297612630). To get to the plaintext, we need one last XOR with IV:

```
P[i] = intermediary[i] ⊕ C[i-1]
P[0] = intermediary[0] ⊕ IV
```

#### Attacking multiple blocks
Extending the attack to work with longer messages is straightforward. Consider a ciphertext with multiple blocks: 

```
IV || C[0] || C[1] || C[2] || ... || C[n]
```

We start decryption of the last block C[n]. Since `P[n] = AES_decrypt(C[n]) ⊕ C[n-1]`, we can manipulate C[n-1] the same way we manipulated IV above. 

After we recover the intermediary value `AES_decrypt(C[n])` by manipulating C[n-1], we continue to recover the intermediary value `AES_decrypt(C[n-1])` by manipulating C[n-2], and so on, until we recover `AES_decrypt(C[0])` by manipulating the prepended IV.  

The beauty of this attack is that it scales efficiently - a 1KB message encrypted with AES-128 (16-byte blocks) would have ~64 blocks, requiring at most 256 * 16 * 8 = 262,144 oracle queries to completely decrypt, which is entirely feasible for an attacker. In practice, it's even less due to statistical optimizations.

#### Exercise - implement padding_oracle_attack_block

Let's start by attacking a single block.

> **Difficulty**: 🔴🔴🔴🔴⚪
> **Importance**: 🔵🔵🔵🔵🔵

Apply the explanation above to implement the `padding_oracle_attack_block()` function.

<details>
<summary>Hint: What is the correct target padding value?</summary>
- When attacking byte i, bytes i+1..15 must have padding value (16-i)
</details>

<details>
<summary>Hint: How do we set the modified IV bytes?</summary>
- For found bytes j > i: modified_iv[j] = intermediate[j] ^ (16-i)
</details>

<details>
<summary>Hint - how do we know when we've found the correct IV byte?</summary>
- When oracle returns padding valid for test value x:
  intermediate[i] = x ^ (16-i)
</details>
"""


# %%
def padding_oracle_attack_block(
    oracle: Callable[[bytes], bool], iv: bytes, block: bytes
) -> bytes:
    """
    Decrypt a single 16-byte ciphertext block using a padding oracle.

    Args:
        oracle: Function that takes IV||block and returns True if padding is valid, False otherwise.
        iv:     The IV or previous ciphertext block (16 bytes)
        block:  The ciphertext block to decrypt (16 bytes)

    Returns:
        Decrypted plaintext block (16 bytes)
    """
    if "SOLUTION":
        assert len(iv) == 16
        assert len(block) == 16

        # We'll discover the intermediate decryption state
        intermediate = bytearray(16)

        # Work backwards from the last byte
        for position in range(15, -1, -1):
            # Padding value we're targeting
            padding_value = 16 - position

            # Start with a zeroed IV
            modified_iv = bytearray(16)

            # Set all bytes after current position to produce correct padding
            for j in range(position + 1, 16):
                modified_iv[j] = intermediate[j] ^ padding_value

            # Brute force the current position
            found = False
            for candidate_byte in range(256):
                modified_iv[position] = candidate_byte

                # Test with oracle
                success = oracle(bytes(modified_iv) + block)
                if success:
                    intermediate[position] = candidate_byte ^ padding_value
                    found = True
                    break

            if not found:
                raise ValueError(
                    f"Failed to find valid padding for position {position}"
                )

        # Recover plaintext by XORing intermediate with original IV
        return bytes(x ^ y for x, y in zip(intermediate, iv))
    else:
        # TODO: Implement single-block padding oracle attack
        #
        # High-level algorithm:
        # 1. For each byte position from 15 down to 0:
        #    a. Calculate the target padding value for the step
        #    b. Initialize modified IV bytes initialized to all zeroes
        #    c. Set the modified IV bytes corresponding to already found intermediary bytes and the target padding
        #    d. Try all 256 values for current position until padding is valid
        #    e. Calculate intermediate value byte from the IV byte that produced valid padding
        #    f. Record the intermediate value byte
        # 2. XOR intermediate values with original IV to get plaintext
        #
        # Hint:
        # - Use bytearray() if you need a mutable byte array, bytes() if you need an immutable one
        pass


@report
def test_padding_oracle_attack_block(
    padding_oracle_attack_block_func, oracle_func: Callable[[bytes], bool] | None = None
):
    # Create a test oracle that knows the secret
    secret_key = b"YELLOW SUBMARINE"
    oracle_call_count = 0

    def t_oracle(ciphertext):
        nonlocal oracle_call_count
        oracle_call_count += 1
        # ciphertext is expected to be IV||C1  (32 bytes)
        if len(ciphertext) != 32:
            return False
        iv = ciphertext[:16]
        encrypted_block = ciphertext[16:]

        cipher = AES.new(secret_key, AES.MODE_ECB)
        intermediary = cipher.decrypt(encrypted_block)
        plaintext_block = bytes(x ^ y for x, y in zip(intermediary, iv))

        padding_length = plaintext_block[-1]
        if padding_length < 1 or padding_length > 16:
            return False
        if len(plaintext_block) < padding_length:
            return False
        for i in range(padding_length):
            if plaintext_block[-(i + 1)] != padding_length:
                return False
        return True

    # plaintext (12 bytes) + padding (4 bytes)
    plaintext = b"HELLO WORLD!"
    padded_plaintext = plaintext + b"\x04" * 4

    # Encrypt with random-ish IV
    iv = b"\x01\xf0\x00\x03\x02\x30\x04\x50\x06\x70\x08\x09\x10\x11\x23\x48"
    cipher = AES.new(
        secret_key, AES.MODE_CBC, iv
    )  # test this with a library implementation of CBC
    ciphertext = cipher.encrypt(padded_plaintext)

    # Run attack
    oracle_func = oracle_func or t_oracle
    recovered = padding_oracle_attack_block_func(t_oracle, iv, ciphertext)
    print(f"Recovered plaintext block in {oracle_call_count} oracle calls:", recovered)
    assert recovered == padded_plaintext, f"Failed to recover: {recovered}"


# Try with internal oracle
test_padding_oracle_attack_block(padding_oracle_attack_block)

# Try with VulnerableServer as oracle
vulnerable_server = VulnerableServer()


def oracle(ciphertext):
    result = vulnerable_server.decrypt_cookie(ciphertext)
    return result == (False, "PADDING_ERROR")


test_padding_oracle_attack_block(padding_oracle_attack_block, oracle_func=oracle)

# %%
"""
#### Exercise - implement padding_oracle_attack

Now let's extend the attack to decrypt entire messages with multiple blocks.

> **Difficulty**: 🔴🔴🔴⚪⚪
> **Importance**: 🔵🔵🔵🔵🔵
"""


# %%
def padding_oracle_attack(oracle: Callable[[bytes], bool], ciphertext: bytes) -> bytes:
    """
    Decrypt an entire CBC-encrypted message using a padding oracle.

    Args:
        oracle: Function that returns True if padding is valid, False otherwise.
        ciphertext: IV || Ciphertext (at least 32 bytes)

    Returns:
        Decrypted plaintext with padding removed
    """
    if "SOLUTION":
        blocks = [ciphertext[i : i + 16] for i in range(0, len(ciphertext), 16)]
        plaintext = b""

        # Decrypt each block using the previous block as IV
        for i in range(1, len(blocks)):
            iv = blocks[i - 1]
            block = blocks[i]

            # Decrypt the block
            plaintext_block = padding_oracle_attack_block(oracle, iv, block)
            plaintext += plaintext_block

        # Remove padding
        return remove_pkcs7_padding(plaintext)
    else:
        # TODO: Implement full padding oracle attack
        # - Use padding_oracle_attack_block() function from earlier
        # - Don't forget to remove padding from the final plaintext (you can use remove_pkcs7_padding() from earlier)
        pass


@report
def test_padding_oracle_attack(
    padding_oracle_attack_func,
    cbc_encrypt_func,
    oracle_func: Callable[[bytes], bool] | None = None,
):
    secret_key = b"YELLOW SUBMARINE"
    oracle_call_count = 0

    def t_oracle(ciphertext):
        nonlocal oracle_call_count
        oracle_call_count += 1
        # ciphertext is expected to be IV||C1  (32 bytes)
        if len(ciphertext) != 32:
            return False
        iv = ciphertext[:16]
        encrypted_block = ciphertext[16:]

        cipher = AES.new(secret_key, AES.MODE_ECB)
        intermediary = cipher.decrypt(encrypted_block)
        plaintext_block = bytes(x ^ y for x, y in zip(intermediary, iv))

        padding_length = plaintext_block[-1]
        if padding_length < 1 or padding_length > 16:
            return False
        if len(plaintext_block) < padding_length:
            return False
        for i in range(padding_length):
            if plaintext_block[-(i + 1)] != padding_length:
                return False
        return True

    # Encrypt with a randomish IV
    original = b"The magic words are squeamish ossifrage"
    iv = b"\x01\xf0\x00\x03\x02\x30\x04\x50\x06\x70\x08\x09\x10\x11\x23\x48"
    ciphertext = iv + cbc_encrypt_func(original, secret_key, iv)

    # Run attack
    oracle_func = oracle_func or t_oracle
    recovered = padding_oracle_attack_func(oracle_func, ciphertext)
    print(f"Recovered plaintext in {oracle_call_count} oracle calls:", recovered)
    assert recovered == original, (
        f"Failed to recover original ({original!r}): {recovered!r}"
    )


test_padding_oracle_attack(padding_oracle_attack, cbc_encrypt)

# %%
"""
<!-- FIXME: bonus exercise: fix the vulnerable server? -->

### Exercise 5: Combining Techniques to Break SSL - The POODLE Attack

Congratulations! You've implemented one of the most elegant attacks in cryptography. 

Now that you've implemented a padding oracle attack, let's explore how one such attach was discovered to break SSL 3.0, affecting millions of web users worldwide, and triggering the end of SSLv3 support in browsers and servers.

**POODLE: Padding Oracle On Downgraded Legacy Encryption**

In October 2014, Google researchers published details of POODLE - a devastating attack that exploited a padding oracle in the context of SSL 3.0. The core issue was that SSL 3.0's specification was **underspecified** regarding CBC padding: padding bytes could contain **arbitrary values** - only the last byte mattered. This meant implementations couldn't validate padding bytes, creating a padding oracle.

POODLE worked by combining three techniques:

1. **Downgrade Attack**: Force browsers to use SSL 3.0 instead of TLS
2. **JavaScript Injection**: Make victim's browser send chosen requests  
3. **Padding Oracle**: Use the SSL 3.0 padding weakness to decrypt byte-by-byte

As long as the attacker had control over the network connection (Man-in-the-Middle, MitM) and could run JavaScript in the victim's browser, they could potentially decrypt parts of encrypted requests, e.g., authentication cookies for sites like Google, or banking sites.

_These assumptions are not far-fetched_:
* We are exposing ourselves to potential men-in-the-middle whenever we access a public network endpoint such as at an airport. Compromised routers are also a common attack vector.
* To run JavaScript in the victim's browser, an attacker could use malicious online adverts (yes, ads can contain custom JavaScript!), [cross-site scripting](https://en.wikipedia.org/wiki/Cross-site_scripting) (XSS), hotspot login screen, or just trick the victim into clicking on a link to a malicious site.

(In the following sections, we'll briefly describe ech of the three techniques involved. If you want more technical details, check out the [original security advisory](https://openssl-library.org/files/ssl-poodle.pdf), or a higher-level description by [Matthew Green](https://blog.cryptographyengineering.com/2014/10/15/attack-of-week-poodle/).)


#### POODLE: Padding Oracle part
The padding oracle attack is slightly different than the one you implemented above. SSL allows arbitrary values in padding, considering only the last one. 

The attacker can manipulate the request length to ensure full padding (16 bytes) is used. The server should then accept only a request which deciphers to 0x10 (16) in the last byte (ignoring the rest), and fail otherwise.

Making another request after a failure will re-run the SSL handshake with a new encryption key. The last byte will decipher to 0x10 in 1 out of 256 attempts on average. The plaintext value of the last byte can then be recovered using an equation equivalent to the one we used in our attack.

#### POODLE: JavaScript Injection part
We said the attacker needs to manipulate the request length. They also need to be able to control the position of a sensitive value (like a cookie) because only the last byte can be recovered.

All of this is possible with our assumption that the attacker can run JavaScript in the victim's browser. A HTTP request with a cookie can look like this:

```
POST /path HTTP/1.1
Cookie: name=value

body 
```

The attacker can change the position of the cookie value, e.g., by changing the request path length. For example, by varying the URL path length (`/a` vs `/aaaaaaaaaa`), the attacker shifts where the cookie appears within the encrypted SSL blocks.

#### POODLE: Downgrade Attack part
The attack relies on the padding used in SSL 3.0. At the time of discovery, TLS 1.0 and 1.1 were already widely used, but many servers still supported SSL 3.0 for compatibility with older clients. 

Clients would normally attempt to use the latest TLS version first, but many implement a protocol downgrade dance to work around server-side interoperability bugs. Unlike proper protocol version negotiation, this downgrade can be triggered by connection drops. An attacker that controls the network can interfere with any attempted handshake offering TLS 1.0 or later, forcing clients to fall back on SSL:

```
Client: "Hi server, let's use TLS 1.2!"
Attacker: blocks connection
Client: "Hmm, that failed. Let's try TLS 1.1!"
Attacker: blocks connection
Client: "Still failing... How about TLS 1.0?"
Attacker: blocks connection
Client: "Fine, let's use SSLv3..."
Server: "Sure, SSLv3 it is!"
Attacker: 😈
```
<!-- FIXME: bonus exercise: implement the JavaScript part -->

#### Exercise: POODLE Lessons Learned

> **Difficulty**: 🔴⚪⚪⚪⚪
> **Importance**: 🔵🔵🔵🔵🔵

The POODLE attack is a great demonstration of how vulnerabilities arise in practice.

- **Weaknesses combine**: POODLE combined a protocol downgrade, a padding oracle, and JavaScript injection. Each of these alone might not be critical, but together they created a devastating attack. This pattern is very common in security. 
- **Protocol design is hard**: SSL 3.0 was designed by security experts and state-of-the-art when introduced, yet the underspecified part caused an exploitable weakness. It's also a reminder of the well-known mantra "Don't roll your own crypto".
- **Yesterday's compatibility is tomorrow's vulnerability**: Things get obsolete over time and new weaknesses are discovered (the vulnerability persisted for **15 years** after TLS 1.0 was standardized!). Supporting legacy systems increases the complexity and attack surface. Whenever possible, kill legacy protocols/systems completely - don't just prefer modern versions, actively reject old ones.
- **Implementation details matter**: Although the TLS protocol was designed to be more secure, security researchers later discovered that many TLS implementations (especially in network hardware) used SSLv3's padding verification code. When you implement a security protocol, validate everything and follow all the details of the specification, they are  there for a reason.
- **One observable difference = total break**: In cryptography (and not only there), even a 1-bit leak can be catastrophic. Invalidating any of the assumptions we make about a system can have very unpredictable effects, and lead to a complete break.

<img src="./resources/dont-roll-crypto.jpg" alt="One does not simply roll their own crypto" style="width: 300px; text-align: center;">

**Here are some quiz questions for you:**

<details>
<summary><b>Question:</b> An attacker needs to decrypt a 20-byte session cookie. Approximately how many HTTPS requests will they need to make?</summary>

20 bytes × 256 attempts per byte = 5,120 requests in the worst case. In practice, some extra requests may be needed to determine the size of cookies if unknown in advance.
</details>

<br>

<details>
<summary><b>Question:</b> How do POODLE's <b>lessons apply directly to AI security?</b></summary>

Examples:
* Protocol Negotiation: Just as browsers downgraded to SSLv3, AI systems might fall back to less secure models or inference modes under pressure.
* One observable difference = total break: Attack allowing to extract even a tiny part of the model's internal state, e.g. a single character from a hidden system prompt, can be compounded to a complete exposure.
* Oracle Attacks: Any observable difference (timing, error messages, token probabilities) can become an oracle. Modern LLMs that reveal confidence scores or alternative completions risk similar attacks.
</details>

<br>

<details>
<summary><b>Question:</b> Why can't the attacker just wait for the victim to naturally visit https://bank.com instead of using JavaScript injection?</summary>

The attacker needs to:
1. Control the request path/body length to position the target byte
2. Make hundreds of requests per byte with slightly different alignments
3. Know exactly what request structure is being sent

Natural browsing doesn't provide this control.
</details>

<br>

<details>
<summary><b>Question:</b> Why does the attacker need to have control over the connection (Man-in-the-Middle) in POODLE? </summary>

Without controlling the connection, the attacker cannot force the client to downgrade to SSL 3.0. It may also be useful to inject JavaScript into the victim's browser, though there are other methods as well.
</details>

<br>

<details>
<summary><b>Question:</b> You're at an airport using public WiFi. Name two ways an attacker could satisfy POODLE's requirements (network control + JavaScript execution).</summary>

Examples:
- Malicious content injected to any HTTP (i.e., unencrypted connection) website you visit
- Fake/compromised WiFi hotspot login page
- DNS hijacking to redirect you to attacker's site
- Compromised router injecting JavaScript into HTTP pages
</details>

#### Defenses Against Padding Oracles
The padding oracle attack can be devastating so let's have a look at some defenses.

**Encrypt-then-MAC**

Always authenticate ciphertext, not plaintext. Verify MAC before attempting decryption.

- Encryption: send `IV || ciphertext || HMAC(mac_key, IV || ciphertext)`
- Decryption and validation: verify HMAC tag first; only then strip the padding. Use a different HMAC key from the one that encrypts.


**Use alternatives to CBC**

If possible, use AEAD (Authenticated Encryption with Associated Data) metods instead of CBC even with encrypt-then-MAC.

Traditional encrypt-then-MAC APIs make the caller juggle two primitives and often get the order wrong. 
AEAD wraps both confidentiality and authenticity into one primitive: a single call encrypts and produces a tag; a single call decrypts and verifies the tag.

**Give attackers nothing to measure**

- Give one generic “decrypt failed” error. Details can be logged locally (if the logs are sufficiently protected), but should not be returned to the client.
- Use same runtime and memory-access for every failure path to prevent timing attacks. Constant-time libraries exist — use them.

**Use modern protocols and keep your crypto library current**

- Most padding-oracle fixes arrive as routine updates.
- Use TLS 1.3+, which was designed with padding oracle resistance in mind.

**Use the strictest security setting possible**

Properly configuring **[CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS)** (Cross-Origin Resource Sharing) headers can prevent cross-origin requests with credentials, and should be a basic practice.

The server can also request the browser to use stricter security settings called **HSTS** (HTTP Strict Transport Security) via the `Strict-Transport-Security` header. One of the settings prevents protocol downgrades, preventing POODLE-like attacks.

<!-- FIXME: forging ciphertext as a bonus exercise -->

"""
# %%
"""
## Summary: Lessons from Cryptographic Implementation

Congratulations! You've implemented fundamental cryptographic primitives and discovered their vulnerabilities. Here are the key takeaways:

### What You've Learned

1. **Cryptographic Primitives Are Complex**
   - MD5 involves intricate bit manipulation and mathematical operations
   - Small implementation errors can completely break security (one of the reasons for the **don't roll your own crypto** mantra)
   - Even "simple" operations like padding require careful validation

2. **Naive Approaches Fail Spectacularly** 
   - Hash(secret||message) seems secure but enables length extension attacks
   - Textbook RSA without padding is completely broken
   - Information leaks as small as "padding valid/invalid" break encryption

3. **Implementation Details Matter Enormously**
   - Timing differences leak information (side channels)
   - Error messages must be identical for all failure cases  
   - Random number generation is critical for security

4. **Real-World Attacks Combine Multiple Techniques**
   - POODLE combined protocol downgrade + JavaScript injection + padding oracle
   - Small vulnerabilities compound into devastating attacks
   - Legacy systems become tomorrow's security holes

5. **In practice**
    - Never roll your own crypto in production systems; use etablished libraries instead
    - Stay current with cryptographic best practices
    - Validate inputs and handle errors consistently
    - Consider side channels in sensitive operations

### Quiz

<details>
<summary>Why shouldn't you use MD5 for password hashing?</summary>
MD5 is too fast - GPUs can compute billions of hashes per second, making brute force feasible
</details>

<details>
<summary>What makes HMAC secure against length extension attacks?</summary>
The double hashing with different keys - even if you extend the inner hash, you need the outer key
</details>

<details>
<summary>Why is padding oracle such a devastating attack?</summary>
A single bit of information (padding valid/invalid) can be leveraged to decrypt entire messages byte by byte
</details>

<details>
<summary>What's the most important lesson about implementing cryptography?</summary>
Don't implement crypto primitives yourself in production - use established, audited libraries
</details>

<!-- FIXME: Further reading -->
"""
