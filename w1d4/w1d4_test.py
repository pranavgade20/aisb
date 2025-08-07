# Allow imports from parent directory
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

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
from aisb_utils import report
import random
from typing import Tuple, List



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
