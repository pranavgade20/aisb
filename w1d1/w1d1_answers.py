
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
    a = 1664525
    c = 1013904223
    m = 2**32
    

    current = seed

    while True:
        current = (a * current + c) % m

        yield current & 0xFF


    # TODO: Implement the LCG keystream generator
    #    - Update state using the LCG formula
    #    - Yield the lowest 8 bits of state as a byte

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
    # TODO: Implement stream cipher encryption
    #   - XOR each byte of plaintext with the bytes from lcg_keystream
    #   - return the resulting ciphertext as bytes


    keystream = lcg_keystream(seed)

    cipher_text = []

    for byte in plaintext:
        keystream_byte = next(keystream)
        cipher_byte = byte ^ keystream_byte
        cipher_text.append(cipher_byte)


    return bytes(cipher_text)
    pass
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
    # TODO: Implement stream cipher decryption
    keystream = lcg_keystream(seed)

    plain_text = []

    for byte in ciphertext:
        keystream_byte = next(keystream)
        plain_byte = byte ^ keystream_byte
        plain_text.append(plain_byte)


    return bytes(plain_text)


    pass
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

    byte0 = keystream_bytes[0]
    byte1 = keystream_bytes[1]

    for bits in range(2**24):
        state0 = byte0 + (bits << 8) | keystream_bytes[0]

        state1 = (a * state0 + c) % m

        if (state1 & 0xFF) == byte1:
            #rearrange to find seed
            seed = ((state0 - c) * pow(a, -1, m)) % m
            return int(seed)

    # TODO: Implement LCG state recovery
    #   - brute-force through all possible upper 24 bits - this will let you try all possible starting states
    #   - for each state, check if it produces the correct bytes
    #   - if it does, calculate the seed by rearranging the LCG formula to get a formula for the seed

    return ValueError("seed not found")
    pass



from w1d1_test import test_lcg_state_recovery


test_lcg_state_recovery(lcg_keystream, recover_lcg_state)






from w1d1_stream_cipher_secrets import intercept_messages

ciphertext1, ciphertext2 = intercept_messages(lcg_encrypt)
print(f"Intercepted ciphertext 1 ({len(ciphertext1)} bytes): {ciphertext1[:50].hex()}...")
print(f"Intercepted ciphertext 2 ({len(ciphertext2)} bytes): {ciphertext2[:50].hex()}...")

# %%


def crib_drag(ciphertext1: bytes, ciphertext2: bytes, crib: bytes) -> list[tuple[int, bytes]]:
    """
    Perform crib-dragging attack on two ciphertexts encrypted with the same keystream.

    Args:
        ciphertext1: First intercepted ciphertext
        ciphertext2: Second intercepted ciphertext
        crib: Known plaintext fragment to try

    Returns:
        List of (position, recovered_text) tuples for further analysis.
    """

    #xor texts

    length = min(len(ciphertext1), len(ciphertext2))

    xor_texts = []
    for i in range(length):
        xor_byte = ciphertext1[i] ^ ciphertext2[i]
        xor_texts.append(xor_byte)

    xor_texts = bytes(xor_texts)

    results = []

    for i in range(len(xor_texts) - len(crib) + 1):
        recovered = []
        for j in range(len(crib)): 
            recovered.append(xor_texts[i+j] ^ crib[j])
        recovered_bytes = bytes(recovered)


        if all(32 <= byte <= 126 for byte in recovered_bytes):
            results.append((i, recovered_bytes))

    return results




    # TODO: Implement crib-dragging
    #   - Use the xor_texts = C1 XOR C2 to find M1 XOR M2
    #   - For each position in xor_texts, XOR the crib with the text at that position
    #   - return a list of tuples (position, recovered_text)

    # Hint:
    # 1. Calculate xor_texts = C1 XOR C2 (which equals M1 XOR M2)
    # 2. For each position from 0 to len(xor_texts) - len(crib):
    #    a. XOR the crib with xor_texts at this position
    #    b. Check if result is readable (all bytes are printable ASCII: 32-126)
    #    c. If readable, add (position, recovered_text) to results
    # 3. Return results list
    pass
from w1d1_test import test_crib_drag


correct_position = test_crib_drag(crib_drag, ciphertext1, ciphertext2)




# %%



def recover_seed(ciphertext: bytes, known_plaintext: bytes, position: int) -> int:
    """
    Recover the original LCG seed from a known plaintext fragment at a specific position.

    This function recovers keystream bytes at the given position, finds the LCG state
    that produced them, then reverses the LCG to find the original seed.

    Args:
        ciphertext: The ciphertext containing the known plaintext
        known_plaintext: The known plaintext fragment
        position: The position where known_plaintext appears in the original message

    Returns:
        The original seed used to encrypt the message
    """
    a = 1664525
    c = 1013904223
    m = 2**32

    keystream_bytes = []
    for i in range(len(known_plaintext)):
        keystream_byte = ciphertext[position+i] ^ known_plaintext[i]
        keystream_bytes.append(keystream_byte)
    
    state_at_position = recover_lcg_state(keystream_bytes)

    a_inv = pow(a, -1, m)
    current_state = state_at_position

    for a in range(position):
        current_state = ((current_state - c) * a_inv) % m

    return current_state

    # TODO: Implement seed recovery
    #   - Use the known plaintext to recover keystream bytes at the given position
    #   - Call recover_lcg_state(keystream_bytes) to get the seed that produces these bytes
    #   - note that the seed at this position is the same as the state - so you can reverse the LCG 'position' times to get back to the original seed
    #
    # Hints:
    # 1. Recover keystream bytes at position:
    #    keystream[i] = ciphertext[position+i] XOR known_plaintext[i]
    # 2. Call recover_lcg_state(keystream) to get the seed that produces these bytes
    # 3. Reverse the LCG 'position' times to get back to the original seed:
    #    - a_inv = pow(a, -1, m)
    #    - state = ((state - c) * a_inv) % m
    # 4. Return the original seed
    pass
from w1d1_test import test_recover_seed


test_recover_seed(recover_seed, lcg_decrypt, ciphertext1, correct_position)


# %%



def recover_messages(
    ciphertext1: bytes, ciphertext2: bytes, known_plaintext: bytes, position: int
) -> tuple[bytes, bytes]:
    """
    Recover both messages using a known plaintext fragment.

    Args:
        ciphertext1: First ciphertext (contains known_plaintext)
        ciphertext2: Second ciphertext
        known_plaintext: Known fragment from message1
        position: Position of known_plaintext in message1

    Returns:
        Tuple of (recovered_message1, recovered_message2)
    """

    seed = recover_seed(ciphertext1, known_plaintext, position)

    plaintext1= lcg_decrypt(seed, ciphertext1)
    plaintext2 = lcg_decrypt(seed, ciphertext2)


    if plaintext1[position:position+len(known_plaintext)] == known_plaintext:
        print("confirmed showing up at position")

        return (plaintext1, plaintext2)
    
    else:
        return (b"", b"")
    # TODO: Implement message recovery using recover_seed
    #   - Call recover_seed to get the original seed
    #   - Use decrypt to get both messages
    #
    # Hints:
    # 1. Call recover_seed(ciphertext1, known_plaintext, position) to get the original seed
    # 2. Use decrypt(seed, ciphertext1) and decrypt(seed, ciphertext2) to decrypt both messages
    # 3. Verify that known_plaintext appears in msg1 at the expected position:
    #    msg1[position:position+len(known_plaintext)] == known_plaintext
    # 4. Return (msg1, msg2) if successful, or (b"", b"") if verification fails
    pass


# Perform the full attack
print("\nPerforming full message recovery...")
recovered_msg1, recovered_msg2 = recover_messages(
    ciphertext1, ciphertext2, b"linear congruential generator", correct_position
)

if recovered_msg1 and recovered_msg2:
    print("\n" + "=" * 60)
    print("RECOVERED MESSAGES:")
    print("\nMessage 1:")
    print(recovered_msg1.decode())
    print("\nMessage 2:")
    print(recovered_msg2.decode())
    print("\n" + "=" * 60)
else:
    print("\nMessage recovery failed!")








## Exercise 2




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
        permute(0b1010, [2, 0, 3, 1], 4) = 0b1100
        Because:
        - Output bit 0 comes from input bit 2 (which is 1)
        - Output bit 1 comes from input bit 0 (which is 1)
        - Output bit 2 comes from input bit 3 (which is 0)
        - Output bit 3 comes from input bit 1 (which is 0)
    """

    result = 0

    for i in range(len(table)):
        bit_position = table[i]

        #shift all right, get target to position 0, mask to get value
        bit_value = (value >> (in_width - 1 - bit_position)) & 1

        result = result | bit_value << (len(table) - 1 - i)

    return result


    # TODO: Implement permutation
    #    - For each position i in the output
    #    - Get the source bit position from table[i]
    #    - Extract that bit from the input
    #    - Place it at position i in the output
    pass


from w1d1_test import test_permute_expand


# Run the test
test_permute_expand(permute_expand)



# %%



def key_schedule(key: int, p10: List[int], p8: List[int]) -> Tuple[int, int]:
    """
    Generate two 8-bit subkeys from a 10-bit key.

    Process:
    1. Apply P10 permutation to the key
    2. Split into left (5 bits) and right (5 bits) halves
    3. Circular left shift both halves by 1 - to get left_half and right_half
    4. Combine the halves and apply P8 to get K1
    5. Circular left shift left_half and right_half (the halves before applying P8) by 2 more (total shift of 3)
    6. Combine the halves and apply P8 to get K2

    Args:
        key: 10-bit encryption key
        p10: Initial permutation table (10 → 10 bits)
        p8: Selection permutation table (10 → 8 bits)

    Returns:
        Tuple of (K1, K2) - the two 8-bit subkeys
    """
    # TODO: Implement key schedule
    #    - Apply P10 permutation
    #    - Split into 5-bit halves
    #    - Generate K1
    #       - Left shift both halves by 1 (LS-1)
    #       - Combine and apply P8
    #    - Generate K2
    #       - Left shift both halves by 2 (LS-2, for total LS-3)
    #       - Combine and apply P8
    #    - you might want to implement left_shift as a helper function
    #       - for example, left_shift 0b10101 by 1 gives 0b01011
    pass
from w1d1_test import test_key_schedule


# Run the test
test_key_schedule(key_schedule, P10, P8)