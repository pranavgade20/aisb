# %%
from typing import Generator


def lcg_keystream(seed: int) -> Generator[int, None, None]:
    a = 1664525
    c = 1013904223
    m = 2**32

    state = seed

    # since we are extracting the last 8 bits
    # we are always going to return a value between 0 and 255
    while True:
        state = (a * state + c) % m
        # Perform bitwise AND on generated number and the hex number FF
        # this makes it so that only the 8 rightmost digits remain, and all the others are converted to 0, which is equivalent to a 8 bit number
        # 255 = 0xFF = 11111111
        yield state & 0xFF


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
    keyStream = lcg_keystream(seed)

    encryption = []

    for byte in plaintext:
        encryption.append(byte ^ next(keyStream))

    return bytes(encryption)


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
    keyStream = lcg_keystream(seed)

    encryption = []

    for byte in ciphertext:
        encryption.append(byte ^ next(keyStream))

    return bytes(encryption)


from w1d1_test import test_decrypt


test_decrypt(lcg_decrypt)
from w1d1_test import test_stream_cipher
