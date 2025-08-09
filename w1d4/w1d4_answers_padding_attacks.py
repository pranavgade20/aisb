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
    byte_length = len(plaintext)
    # calculate how much padding is needed to the nearest multiple of 'block size'
    # e.g. if we have a block size of 4 and length is 7, then we know
    # 7 mod 4 is 3 and we need 4 - 3 = 1 bytes of padding
    padding_length = block_size - (byte_length % block_size)
    
    padded = plaintext + bytes([padding_length])*padding_length
    # bytes([padding_length]) returns '\x10', i.e. the hex representation of the decimal number 16

    return padded


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
    # TODO: Implement PKCS#7 unpadding with validation
    if len(padded_text) == 0:
        raise InvalidPaddingError('Padded text has length 0')

    padding_length = padded_text[-1]
    if padding_length < 1 or padding_length > block_size:       
        raise InvalidPaddingError('Padding length exceeds block size')

    if len(padded_text) < padding_length:
        raise InvalidPaddingError('Padded text must be longer than the length of the padding.')

    for i in range(padding_length):
        if padded_text[-(i + 1)] != padding_length:
            raise InvalidPaddingError("Inconsistent padding bytes")

    unpadded = padded_text[:-padding_length] 

    return unpadded


from w1d4_test import test_remove_pkcs7_padding


test_remove_pkcs7_padding(remove_pkcs7_padding, InvalidPaddingError)

# %%
from Crypto.Cipher import AES

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    assert len(a) == len(b), "Byte strings must have equal length"
    return bytes(x ^ y for x, y in zip(a, b))


def single_block_aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    assert len(plaintext) == 16, "Plaintext must be 16 bytes"
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

# %%
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
    # TODO: Implement CBC encryption
    block_size = len(iv)
    padded = add_pkcs7_padding(plaintext, block_size)

    blocks = [padded[i:i+block_size] for i in range(0, len(padded), block_size)]
    
    C = iv
    cipherblocks = []
    for i in range(len(blocks)):
        P = blocks[i]
        E = xor_bytes(P, C)
        C_next = single_block_aes_encrypt(E, key)
        cipherblocks.append(C_next)
        C = C_next 

    ciphertext = b''.join(cipherblocks)
    return ciphertext

from w1d4_test import test_cbc_encrypt


test_cbc_encrypt(cbc_encrypt)

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
    # TODO: Implement CBC decryption
    block_size = len(iv)

    cipherblocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    
    blocks = []
    for i in reversed(range(len(cipherblocks))):
        C = cipherblocks[i]
        E = single_block_aes_decrypt(C, key)
        if i == 0:
            C_prev = iv
        else:
            C_prev = cipherblocks[i-1]

        P = xor_bytes(C_prev, E)
        blocks.append(P)
    # need to reverse the list because we're decrypting from the end, so the plaintext blocks are: [P4, P3, ...]
    blocks = reversed(blocks) 
    padded = b''.join(blocks)
    plaintext = remove_pkcs7_padding(padded, block_size)

    return plaintext
    
from w1d4_test import test_cbc_decrypt


test_cbc_decrypt(cbc_decrypt, cbc_encrypt, InvalidPaddingError)

# %%
