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
    p = get_prime(bits // 2)
    q = get_prime(bits // 2)

    if p == q:
        raise ValueError("p and q must not be equal!")

    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = 2**16 + 1
    d = pow(e, -1, phi_n)

    return (n, e), (n, d)


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
    
    msg_bytes = bytes(message, encoding='utf-8')

    msg_bytes_encrypted = []
    for byte in msg_bytes:
        c = byte**e % n
        msg_bytes_encrypted.append(c)

    return msg_bytes_encrypted

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
    #    - Decrypt each value with pow(c, d, n)
    #    - Convert to bytes and decode UTF-8
    n, d = private_key
    
    msg_bytes_decrypted = []
    for char in ciphertext:
        m = char**d % n
        msg_bytes_decrypted.append(m)

    return bytes(msg_bytes_decrypted).decode('utf-8')

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
    # TODO: Implement signing
    #    - Extract n and d from private_key
    #    - Convert message to bytes
    #    - Sign each byte with pow(byte, d, n)
    n, d = private_key

    msg_bytes = bytes(message, encoding='utf-8')

    msg_bytes_encrypted = []
    for byte in msg_bytes:
        c = byte**d % n
        msg_bytes_encrypted.append(c)
    
    return msg_bytes_encrypted

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
    # TODO: Implement verification
    #    - Extract n and e from public_key
    #    - Recover each byte with pow(s, e, n)
    #    - Check if recovered bytes match original message
    #    - Return False for any errors
    n, e = public_key
    
    msg_bytes_decrypted = []
    for char in signature:
        m = char**e % n
        msg_bytes_decrypted.append(m)

    for b in msg_bytes_decrypted:
        if b not in range(0, 256):
            print('checked bytes were be in range (0, 256)')
            return False

    new_message = bytes(msg_bytes_decrypted).decode('utf-8')
    
    return new_message == message

from w1d4_test import test_signatures

test_signatures(sign, verify, generate_keys)

# %%
