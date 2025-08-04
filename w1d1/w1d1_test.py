# Allow imports from parent directory
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import os
import sys
from typing import Generator, List, Tuple, Callable
from aisb_utils import report
from typing import Generator
from w1d1_stream_cipher_secrets import intercept_messages
import random
from typing import List, Tuple
import random
import time
from typing import List
import random
import random



@report
def test_lcg_keystream(lcg_keystream):
    """Test the LCG keystream generator."""
    print("Testing LCG keystream...")

    # Test 1: Basic functionality
    ks = lcg_keystream(1)
    first_five = [next(ks) for _ in range(5)]
    print(f"First 5 bytes: {first_five}")
    assert first_five == [108, 219, 126, 197, 96], "First five bytes do not match expected values"

    # Test 2: Deterministic output
    ks2 = lcg_keystream(1)
    second_five = [next(ks2) for _ in range(5)]
    assert first_five == second_five, "Keystream should be deterministic for the same seed"

    print("✓ LCG keystream tests passed!\n" + "=" * 60)




@report
def test_encrypt(encrypt):
    """Test the encrypt function."""
    print("Testing encrypt function...")

    # Test 1: Basic encryption
    seed = 12345
    plaintext = b"Hello, World!"
    ciphertext = encrypt(seed, plaintext)
    print([hex(b) for b in ciphertext])
    assert ciphertext == bytes([0x0C, 0xB6, 0x7A, 0x11, 0xD7, 0x9B, 0x8A, 0x56, 0x03, 0xA9, 0x12, 0xA1, 0x41]), (
        "Encryption output does not match expected"
    )
    print("✓ Tests for encrypt function passed!\n" + "=" * 60)




@report
def test_decrypt(decrypt):
    """Test the decrypt function."""
    print("Testing decrypt function...")

    # Test 1: Basic decryption
    seed = 12345
    ciphertext = bytes([0x0C, 0xB6, 0x7A, 0x11, 0xD7, 0x9B, 0x8A, 0x56, 0x03, 0xA9, 0x12, 0xA1, 0x41])
    plaintext = decrypt(seed, ciphertext)
    assert plaintext == b"Hello, World!", "Decryption output does not match expected"
    print("✓ Tests for decrypt function passed!\n" + "=" * 60)


# %%


@report
def test_stream_cipher(lcg_keystream, encrypt, decrypt):
    """Test the stream cipher implementation."""
    print("Testing stream cipher implementation...")

    # Test 1: Basic encryption/decryption
    seed = 12345
    plaintext = b"Hello, World!"
    ciphertext = encrypt(seed, plaintext)
    decrypted = decrypt(seed, ciphertext)

    print(f"Plaintext:  {plaintext}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Decrypted:  {decrypted}")
    assert decrypted == plaintext, "Decryption failed to recover plaintext"

    # Test 2: Different seeds produce different ciphertexts
    ciphertext2 = encrypt(seed + 1, plaintext)
    assert ciphertext != ciphertext2, "Different seeds should produce different ciphertexts"

    # Test 3: Same seed produces same keystream
    ct1 = encrypt(seed, b"Test message")
    ct2 = encrypt(seed, b"Test message")
    assert ct1 == ct2, "Same seed should produce same ciphertext"

    # Test 4: Stream property (can encrypt byte by byte)
    full_ct = encrypt(seed, b"ABCD")
    ks = lcg_keystream(seed)
    byte_ct = bytes([b ^ next(ks) for b in b"ABCD"])
    assert full_ct == byte_ct, "Stream cipher should work byte by byte"

    print("✓ Stream cipher tests passed!\n" + "=" * 60)




@report
def test_lcg_state_recovery(lcg_keystream, recover_lcg_state):
    """Test LCG state recovery."""
    print("Testing LCG state recovery...")

    # Generate some keystream bytes
    seed = 12345678
    ks = lcg_keystream(seed)
    bytes_observed = [next(ks) for _ in range(5)]
    print(f"Observed keystream bytes: {bytes_observed}")

    # Recover the seed
    recovered_seed = recover_lcg_state(bytes_observed)
    print(f"Original seed: {seed}")
    print(f"Recovered seed: {recovered_seed}")

    # Verify it produces the same keystream
    ks_test = lcg_keystream(recovered_seed)
    bytes_test = [next(ks_test) for _ in range(5)]
    assert bytes_test == bytes_observed, "Recovered seed doesn't produce same keystream"

    print("✓ LCG state recovery successful!\n" + "=" * 60)




@report
def test_crib_drag(crib_drag, ciphertext1, ciphertext2):
    """Test the crib-dragging attack."""
    print("Testing crib-dragging attack...")

    # The crib we'll use - we suspect this phrase appears in one of the messages
    crib = b"linear congruential generator"

    # Perform the attack
    results = crib_drag(ciphertext1, ciphertext2, crib)[:10]  # Limit to first 10 results for brevity

    print(f"\nTrying crib: '{crib.decode()}'")
    print(f"Found {len(results)} potential matches:\n")

    for pos, recovered in results:
        print(f"Position {pos}: '{recovered.decode()}'")

    # The correct position should reveal part of message2
    assert len(results) > 0, "No matches found - check your implementation"

    # Find the most likely match (usually the one that makes most sense)
    correct_pos = 2  # This is where "linear congruential generator" appears in message1

    print(f"\n✓ The crib appears to be at position {correct_pos}!")
    print("This reveals part of the other message.\n" + "=" * 60)

    return correct_pos




@report
def test_recover_seed(recover_seed, decrypt, ciphertext1, correct_position):
    """Test seed recovery."""
    print("Testing seed recovery...")

    # Use our known crib and position
    recovered = recover_seed(ciphertext1, b"linear congruential generator", correct_position)
    print(f"Recovered seed: {recovered}")

    # Verify by decrypting
    test_msg = decrypt(recovered, ciphertext1)
    print(f"Recovered message: {test_msg.decode()[:50]}...")
    assert b"linear congruential generator" in test_msg, "Seed recovery failed"

    print("✓ Seed recovery successful!\n" + "=" * 60)




@report
def test_permute_expand(permute_expand):
    """Test the permutation function."""
    print("Testing permutation...")

    # Test 1: Identity permutation
    identity = list(range(8))
    assert permute_expand(0b10110011, identity, 8) == 0b10110011, "Identity permutation failed"

    # Test 2: Reverse permutation
    reverse = list(range(7, -1, -1))
    assert permute_expand(0b10000000, reverse, 8) == 0b00000001, "Reverse permutation failed"
    assert permute_expand(0b11110000, reverse, 8) == 0b00001111, "Reverse permutation failed"

    # Test 3: Expansion permutation (E/P in DES)
    # This duplicates some bits
    expansion = [3, 0, 1, 2, 1, 2, 3, 0]  # 4 bits → 8 bits
    result = permute_expand(0b1010, expansion, 4)
    print(f"Expansion of 0b1010: 0b{result:08b}")
    assert result == 0b01010101, "Expansion permutation failed"

    # Test 4: Compression permutation (P6 in DES)
    # This selects a subset of bits
    compression = [1, 3, 4, 6, 7, 9]  # 10 bits → 6 bits (select 6 from 10)
    result = permute_expand(0b1010101010, compression, 10)
    print(f"Compression of 0b1010101010: 0b{result:06b}")
    assert result == 0b001100, "Compression permutation failed"

    print("✓ Permutation tests passed!\n" + "=" * 60)




@report
def test_key_schedule(key_schedule, P10, P8):
    """Test the key schedule functions."""
    print("Testing key schedule...")

    # Test key schedule with known values
    # Test key: 0b1010000010
    test_key = 0b1010000010
    k1, k2 = key_schedule(test_key, P10, P8)
    print(f"Key: 0b{test_key:010b}")
    print(f"K1:  0b{k1:08b}")
    print(f"K2:  0b{k2:08b}")

    # Verify subkeys are different
    assert k1 != k2, "Subkeys should be different"

    # Test with all-zero key
    k1_zero, k2_zero = key_schedule(0, P10, P8)
    assert k1_zero == k2_zero == 0, "All-zero key should produce all-zero subkeys"

    # Test with all-one key
    k1_ones, k2_ones = key_schedule(0b1111111111, P10, P8)
    print(f"\nAll-ones key subkeys: K1=0b{k1_ones:08b}, K2=0b{k2_ones:08b}")

    print("✓ Key schedule tests passed!\n" + "=" * 60)




@report
def test_sbox_lookup(sbox_lookup, S0, S1):
    """Test the S-box lookup function."""
    print("Testing S-box lookup...")

    # Verify some known values
    assert sbox_lookup(S0, 0b0000) == S0[0][0], "S0 lookup failed for 0000"
    assert sbox_lookup(S1, 0b1111) == S1[3][3], "S1 lookup failed for 1111"

    # Test all possible 4-bit inputs
    for i in range(16):
        s0_out = sbox_lookup(S0, i)
        s1_out = sbox_lookup(S1, i)
        assert s0_out == S0[((i >> 3) & 1) << 1 | (i & 1)][((i >> 2) & 1) << 1 | ((i >> 1) & 1)], (
            f"S0 lookup failed for {i:04b}"
        )
        assert s1_out == S1[((i >> 3) & 1) << 1 | (i & 1)][((i >> 2) & 1) << 1 | ((i >> 1) & 1)], (
            f"S1 lookup failed for {i:04b}"
        )

    print("✓ S-box lookup tests passed!\n" + "=" * 60)




@report
def test_feistel(sbox_lookup, fk, EP, S0, S1, P4):
    """Test the Feistel function components."""
    print("Testing Feistel function...")

    # Test S-box lookup
    # Test all possible 4-bit inputs
    print("S-box S0:")
    for i in range(16):
        result = sbox_lookup(S0, i)
        if i % 4 == 0:
            print()
        print(f"  {i:2d} → {result}", end="")
    print("\n")

    # Test Feistel function
    left = 0b1100
    right = 0b0110
    subkey = 0b10101010

    new_left, new_right = fk(left, right, subkey, EP, S0, S1, P4)

    print(f"Input:  L={left:04b}, R={right:04b}")
    print(f"Subkey: {subkey:08b}")
    print(f"Output: L={new_left:04b}, R={new_right:04b}")

    # Verify right half unchanged
    assert new_right == right, "Right half should not change"

    # Test with different inputs
    test_cases = [
        (0b0000, 0b0000, 0b00000000),
        (0b1111, 0b1111, 0b11111111),
        (0b1010, 0b0101, 0b11001100),
    ]

    print("\nAdditional test cases:")
    for l, r, k in test_cases:
        nl, nr = fk(l, r, k, EP, S0, S1, P4)
        print(f"  fk({l:04b}, {r:04b}, {k:08b}) = ({nl:04b}, {nr:04b})")
        # Verify right half unchanged for all test cases
        assert nr == r, f"Right half should not change in Feistel function for input ({l:04b}, {r:04b}, {k:08b})"

    print("✓ Feistel function tests passed!\n" + "=" * 60)




@report
def test_des_complete(process_byte, encrypt, decrypt, key_schedule, P10, P8, IP, IP_INV, EP, S0, S1, P4):
    """Test complete DES encryption/decryption."""
    print("Testing complete DES...")

    # Test single byte encryption/decryption
    key = 0b1010000010
    k1, k2 = key_schedule(key, P10, P8)

    plaintext = 0b11010111
    ciphertext = process_byte(plaintext, k1, k2, IP, IP_INV, EP, S0, S1, P4)
    decrypted = process_byte(ciphertext, k2, k1, IP, IP_INV, EP, S0, S1, P4)

    print(f"Key:        0b{key:010b}")
    print(f"Plaintext:  0b{plaintext:08b}")
    print(f"Ciphertext: 0b{ciphertext:08b}")
    print(f"Decrypted:  0b{decrypted:08b}")

    assert decrypted == plaintext, "Decryption failed"

    # Test full message
    message = b"Hello!"
    encrypted = encrypt(key, message)
    decrypted = decrypt(key, encrypted)

    print(f"\nMessage:   {message}")
    print(f"Encrypted: {encrypted.hex()}")
    print(f"Decrypted: {decrypted}")

    assert decrypted == message, "Message decryption failed"

    # Test avalanche effect
    key2 = key ^ 1  # Flip one bit in key
    encrypted2 = encrypt(key2, message)
    diff_bytes = sum(1 for a, b in zip(encrypted, encrypted2) if a != b)
    assert diff_bytes > 0, "Avalanche effect should change at least some bytes"
    print(f"\nAvalanche: {diff_bytes}/{len(message)} bytes changed with 1-bit key difference")

    print("✓ DES tests passed!\n" + "=" * 60)




@report
def test_meet_in_the_middle(meet_in_the_middle_attack, double_encrypt):
    """Test the meet-in-the-middle attack."""
    print("Testing meet-in-the-middle attack on Double DES...")

    import random
    import time

    # Use smaller keys for faster testing
    random.seed(42)
    key1 = random.randrange(0, 1024)
    key2 = random.randrange(0, 1024)

    print(f"True keys: k1={key1}, k2={key2}")

    # Create known plaintext-ciphertext pair
    plaintext = b"Attack!"
    ciphertext = double_encrypt(key1, key2, plaintext)

    print(f"Plaintext:  {plaintext}")
    print(f"Ciphertext: {ciphertext.hex()}")

    # Perform attack
    print("\nPerforming meet-in-the-middle attack...")
    start_time = time.time()
    found_keys = meet_in_the_middle_attack(plaintext, ciphertext)
    attack_time = time.time() - start_time

    print(f"Attack completed in {attack_time:.2f} seconds")
    print(f"Found {len(found_keys)} valid key pair(s)")

    # Check if true keys were found
    true_found = False
    for k1, k2 in found_keys[:5]:  # Show first 5
        is_true = k1 == key1 and k2 == key2
        marker = " ← TRUE KEYS!" if is_true else ""
        print(f"  k1={k1}, k2={k2}{marker}")
        if is_true:
            true_found = True

    if len(found_keys) > 5:
        print(f"  ... and {len(found_keys) - 5} more")

    assert true_found, "Failed to find the true keys"

    # Verify all found keys work
    for k1, k2 in found_keys:
        assert double_encrypt(k1, k2, plaintext) == ciphertext, f"Invalid keys found: {k1}, {k2}"

    # Compare with brute force time (estimated)
    brute_force_ops = 1024 * 1024
    mitm_ops = 2 * 1024
    print(f"\nComplexity reduction: {brute_force_ops:,} → {mitm_ops:,} operations")
    print(f"Speedup factor: {brute_force_ops / mitm_ops:.0f}x")

    print("✓ Meet-in-the-middle attack succeeded!\n" + "=" * 60)




@report
def test_substitute(substitute, SBOX):
    """Test the S-box substitution function."""
    print("Testing S-box substitution...")

    # Test 1: Identity S-box
    identity_sbox = list(range(16))
    assert substitute(0x1234, identity_sbox) == 0x1234, "Identity S-box should not change the value"

    # Test 2: Simple substitution
    simple_sbox = [15 - i for i in range(16)]  # Reverse mapping: 0→15, 1→14, etc.
    # 0x1234 has nibbles: 4, 3, 2, 1
    # After substitution: 11, 12, 13, 14 = 0xBCDE
    assert substitute(0x1234, simple_sbox) == 0xEDCB, "Simple substitution failed"

    # Test 3: Real S-box from the cipher
    result = substitute(0x5A5A, SBOX)
    print(f"S-box substitution of 0x5A5A: 0x{result:04X}")
    assert result == 0x5F5F, "Real S-box substitution failed"

    print("✓ S-box substitution tests passed!\n" + "=" * 60)




@report
def test_permute(permute, PBOX):
    """Test the P-box permutation function."""
    print("Testing P-box permutation...")

    # Test 1: Identity permutation
    identity_pbox = list(range(16))
    assert permute(0xABCD, identity_pbox) == 0xABCD, "Identity permutation should not change the value"

    # Test 2: Reverse permutation
    reverse_pbox = list(range(15, -1, -1))  # [15, 14, 13, ..., 1, 0]
    # This reverses all bits
    assert permute(0x8000, reverse_pbox) == 0x0001, "Reverse permutation failed for single bit"
    assert permute(0x1234, reverse_pbox) == 0x2C48, "Reverse permutation failed"

    # Test 3: Real P-box from the cipher
    result = permute(0x5555, PBOX)
    print(f"P-box permutation of 0x5555: 0x{result:04X}")

    # Test 4: Verify single bit movement
    for i in range(16):
        input_val = 1 << (15 - i)  # Single bit at position i
        output = permute(input_val, PBOX)
        # Find where the bit ended up
        for j in range(16):
            if output & (1 << (15 - j)):
                print(f"Bit {i} → Bit {j}")
                break

    print("✓ P-box permutation tests passed!\n" + "=" * 60)




@report
def test_block_cipher(encrypt_block, decrypt_block, round_keys, SBOX, PBOX, INV_SBOX, INV_PBOX):
    """Test the block cipher encryption and decryption."""
    print("Testing block cipher...")

    # Test 1: Encrypt and decrypt should be inverses
    key = 0x1337
    keys = round_keys(key)
    plaintext = 0xBEEF

    ciphertext = encrypt_block(plaintext, keys, SBOX, PBOX)
    decrypted = decrypt_block(ciphertext, keys, INV_SBOX, INV_PBOX)

    print(f"Plaintext:  0x{plaintext:04X}")
    print(f"Ciphertext: 0x{ciphertext:04X}")
    print(f"Decrypted:  0x{decrypted:04X}")

    assert decrypted == plaintext, "Decryption failed to recover plaintext"

    # Test 2: Different keys should give different ciphertexts
    keys2 = round_keys(0xDEAD)
    ciphertext2 = encrypt_block(plaintext, keys2, SBOX, PBOX)
    assert ciphertext != ciphertext2, "Different keys should produce different ciphertexts"

    # Test 3: Avalanche effect - small change in plaintext
    plaintext2 = plaintext ^ 1  # Flip one bit
    ciphertext3 = encrypt_block(plaintext2, keys, SBOX, PBOX)
    diff_bits = bin(ciphertext ^ ciphertext3).count("1")
    print(f"\nAvalanche effect: {diff_bits} bits changed (out of 16)")
    assert diff_bits > 2, "Cipher should have good avalanche effect"

    print("✓ Block cipher tests passed!\n" + "=" * 60)




@report
def test_ecb_mode(encrypt, decrypt, SBOX, PBOX, INV_SBOX, INV_PBOX):
    """Test ECB mode encryption and decryption."""
    print("Testing ECB mode...")

    # Test 1: Basic encryption/decryption
    key = 0xCAFE
    message = b"Hello, World"

    ciphertext = encrypt(key, message, SBOX, PBOX)
    decrypted = decrypt(key, ciphertext, INV_SBOX, INV_PBOX)

    print(f"Original:  {message}")
    print(f"Encrypted: {ciphertext.hex()}")
    print(f"Decrypted: {decrypted}")

    assert decrypted == message, "Decryption failed to recover message"

    # Test 2: Odd length message (tests padding)
    odd_message = b"Hello"
    ciphertext2 = encrypt(key, odd_message, SBOX, PBOX)
    decrypted2 = decrypt(key, ciphertext2, INV_SBOX, INV_PBOX)
    assert decrypted2 == odd_message, "Failed with odd-length message"

    # Test 3: ECB pattern weakness
    # Repeating blocks should encrypt to the same ciphertext
    pattern_msg = b"ABCDABCD"
    pattern_ct = encrypt(key, pattern_msg, SBOX, PBOX)
    # First 2 bytes should equal bytes 4-6, second 2 bytes should equal bytes 6-8
    assert pattern_ct[0:2] == pattern_ct[4:6], "ECB should preserve patterns"
    assert pattern_ct[2:4] == pattern_ct[6:8], "ECB should preserve patterns"

    print("✓ ECB mode tests passed!\n" + "=" * 60)
