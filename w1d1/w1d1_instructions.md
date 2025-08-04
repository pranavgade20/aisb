
# W1D1 - Cryptography 1: Stream Ciphers and Block Ciphers

Today you'll learn about fundamental encryption techniques by implementing stream ciphers and block ciphers from scratch. You'll build a Linear Congruential Generator (LCG) based stream cipher, exploit its weaknesses through crib-dragging attacks, implement a simplified DES cipher, and explore the meet-in-the-middle attack that breaks double encryption.

Understanding these primitives will give you insight into both the power and limitations of cryptographic systems, and why certain design choices matter for security.

## Table of Contents

- [Content & Learning Objectives](#content--learning-objectives)
    - [1️⃣ Stream Ciphers & Linear Congruential Generators](#-stream-ciphers--linear-congruential-generators)
    - [2️⃣ Block Ciphers: Simplified DES](#-block-ciphers-simplified-des)
    - [3️⃣ Block Ciphers: Substitution-Permutation Networks](#-block-ciphers-substitution-permutation-networks)
- [1️⃣ Stream Ciphers & Linear Congruential Generators](#-stream-ciphers--linear-congruential-generators-)
    - [Stream Ciphers and Pseudorandom Generators](#stream-ciphers-and-pseudorandom-generators)
    - [Tips for exercises](#tips-for-exercises)
    - [Exercise 1.1: Implementing a Linear Congruential Generator (LCG)](#exercise--implementing-a-linear-congruential-generator-lcg)
    - [Exercise 1.2: Building a Stream Cipher](#exercise--building-a-stream-cipher)
    - [Stream Cipher Security](#stream-cipher-security)
        - [Why LCG is Not Cryptographically Secure](#why-lcg-is-not-cryptographically-secure)
        - [Real Cryptographic Stream Ciphers](#real-cryptographic-stream-ciphers)
        - [The Importance of Key Reuse](#the-importance-of-key-reuse)
        - [Next Steps](#next-steps)
    - [Exercise 1.3: Breaking Stream Ciphers with Crib-Dragging](#exercise--breaking-stream-ciphers-with-crib-dragging)
    - [Exercise 1.3a: LCG State Recovery](#exercise-a-lcg-state-recovery)
    - [Exercise 1.3b: The Crib-Dragging Attack](#exercise-b-the-crib-dragging-attack)
    - [Exercise 1.3c: Full Message Recovery](#exercise-c-full-message-recovery)
    - [Summary: What We've Learned](#summary-what-weve-learned)
    - [Preventing These Attacks](#preventing-these-attacks)
    - [Stretch: Automated Crib-Dragging](#stretch-automated-crib-dragging)
- [2️⃣ Block Ciphers: Simplified DES](#-block-ciphers-simplified-des-)
    - [Understanding Feistel Ciphers](#understanding-feistel-ciphers)
    - [DES Components](#des-components)
    - [Exercise 2.1: Understanding Permutations and Expansions](#exercise--understanding-permutations-and-expansions)
    - [Exercise 2.2: Key Schedule - Generating Subkeys](#exercise--key-schedule---generating-subkeys)
    - [Exercise 2.3: The Feistel Function (fk)](#exercise--the-feistel-function-fk)
    - [Exercise 2.4: Complete DES Encryption](#exercise--complete-des-encryption)
    - [Exercise 2.5: Meet-in-the-Middle Attack on Double DES](#exercise--meet-in-the-middle-attack-on-double-des)
- [3️⃣ Block Ciphers: Substitution-Permutation Networks](#-block-ciphers-substitution-permutation-networks-)
    - [Understanding Substitution-Permutation Networks](#understanding-substitution-permutation-networks)
    - [Key Properties of Secure Block Ciphers](#key-properties-of-secure-block-ciphers)
    - [Exercise 3.1: Implementing S-box Substitution](#exercise--implementing-s-box-substitution)
    - [Exercise 3.2: Implementing P-box Permutation](#exercise--implementing-p-box-permutation)
    - [Exercise 3.3: Building the Complete Block Cipher](#exercise--building-the-complete-block-cipher)
    - [Exercise 3.4: Implementing ECB Mode](#exercise--implementing-ecb-mode)
- [Further reading](#further-reading)

## Content & Learning Objectives

### 1️⃣ Stream Ciphers & Linear Congruential Generators
In the first exercise, you'll implement an LCG, one of the simplest pseudorandom number generators. Then you'll build a stream cipher using this LCG and we'll talk about its fundamental properties and weaknesses.

> **Learning Objectives**
> - Implement a Linear Congruential Generator (LCG) for keystream generation
> - Build encryption and decryption functions using XOR operations
> - Understand the security properties and limitations of stream ciphers
> - Perform state recovery attacks on predictable pseudorandom generators
> - Execute crib-dragging attacks to break key-reused stream ciphers
> - Learn why modern stream ciphers use nonces and proper key management

### 2️⃣ Block Ciphers: Simplified DES

You'll implement a simplified version of the Data Encryption Standard to understand Feistel network principles.

> **Learning Objectives**
> - Understand the mathematical foundation of pseudorandom number generators
> - Implement an LCG and use it to generate a keystream
> - Build the complete Feistel cipher encryption and decryption process
> - Learn the structure and security principles behind classic block ciphers
> - Execute meet-in-the-middle attacks to demonstrate why double encryption fails
> - Understand time-memory tradeoffs in advanced cryptanalytic techniques

### 3️⃣ Block Ciphers: Substitution-Permutation Networks

You'll build a simplified AES-like cipher to understand modern block cipher design principles.

> **Learning Objectives**
> - Implement S-box substitution for providing confusion in block ciphers
> - Build P-box permutation operations for achieving diffusion
> - Construct complete substitution-permutation network ciphers
> - Understand the principles of confusion and diffusion in cryptographic design
> - Implement Electronic Codebook (ECB) mode for encrypting full messages
> - Learn the limitations and security weaknesses of basic block cipher modes



## 1️⃣ Stream Ciphers & Linear Congruential Generators

Cryptographic primitives are the basic building blocks of secure systems. Understanding how they work—and how they can be broken—is essential for both implementing secure systems and identifying vulnerabilities.

**Stream ciphers** encrypt data by generating a pseudorandom keystream and XORing it with the plaintext. They're fast and work well for real-time applications, but require that each key is used only once. Examples include RC4 (now deprecated) and ChaCha20 (modern and secure).

**Block ciphers** encrypt fixed-size blocks of data using complex mathematical operations. They form the foundation of most encryption systems today, though they require additional modes of operation to encrypt arbitrary-length data. The most important example is AES (Advanced Encryption Standard).
In this section, you'll implement a Linear Congruential Generator (LCG) to generate a keystream, use it to create a stream cipher to encrypt and decrypt messages, and finally break the cipher using a technique called crib-dragging.

<details>
<summary>Vocabulary: Cryptographic Terms</summary><blockquote>

- **Pseudorandom Number Generator (PRNG)**: An algorithm that produces a sequence of numbers that appears random but is actually deterministic given an initial seed.
- **Plaintext**: The original, unencrypted data
- **Ciphertext**: The encrypted result
- **Key**: Secret information used to control encryption/decryption
- **Keystream**: The pseudorandom sequence generated by a stream cipher
- **Block**: A fixed-size chunk of data processed by a block cipher
- **Forward secrecy**: The property that compromising long-term keys does not compromise past session keys

</blockquote></details>


### Stream Ciphers and Pseudorandom Generators

Stream ciphers encrypt data by generating a pseudorandom keystream and XORing it with the plaintext. Unlike block ciphers that process fixed-size chunks, stream ciphers can encrypt data of any length, making them ideal for real-time communications and streaming applications.

The security of a stream cipher depends entirely on the unpredictability of its keystream. If an attacker can predict even part of the keystream, they can decrypt the corresponding plaintext. This is why the quality of the pseudorandom generator is crucial.

**Linear Congruential Generators (LCGs)** are among the simplest pseudorandom generators, using the formula:
$$X_{n+1} = (a × X_n + c) \mod m$$
where X is the sequence of pseudorandom values, and a, c, and m are carefully chosen constants.

While LCGs are fast and easy to implement, they have fatal cryptographic weaknesses:
- **Predictability**: Just a few consecutive outputs reveal the internal state and allow an attacker to predict all future output.
- **Short periods**: Limited randomness compared to cryptographic generators
- **Statistical bias**: Patterns emerge that can be exploited

Despite these flaws, LCGs remain useful for non-security applications like simulations where speed matters more than unpredictability.

**Modern stream ciphers** like ChaCha20 use sophisticated constructions with large internal states and complex non-linear operations to resist cryptanalysis. They're designed to be indistinguishable from truly random sequences.

### Tips for exercises
Before starting with the exercises, make sure you have all the prerequisites from [setup instructions](../README.md#setup) and read the [in-person instructions](../README.md#in-person-instructions).

The recommended way to complete the exercises is to make a new `.py` file (suggested name: `w#d#_answers.py`) in this directory and copy the code snippets from this file into it as you go along.

Use`# %%` lines to turn the code into executable cells in VS Code. You can then run the cells to execute your code and the provided tests.

For the sake of the exercise, **aim for correctness, not efficiency.**


```python

# %%

import os
import sys
from typing import Generator, List, Tuple, Callable

# Allow imports from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from aisb_utils import report
```

### Exercise 1.1: Implementing a Linear Congruential Generator (LCG)

> **Difficulty**: 🔴⚪⚪⚪⚪
> **Importance**: 🔵🔵🔵⚪⚪
>
> You should spend up to ~10 minutes on this exercise.

An LCG generates a sequence of numbers using the recurrence relation:
```
X_{n+1} = (a * X_n + c) mod m
```

Where:
- X_n is the current state
- a is the multiplier
- c is the increment
- m is the modulus

We'll use the parameters from Numerical Recipes (a popular choice):
- a = 1664525
- c = 1013904223
- m = 2^32

<details>
<summary>Vocabulary: LCG Terms</summary><blockquote>

- **Recurrence relation**: A formula that defines each term of a sequence using previous terms
- **Modulus (m)**: The value that wraps the sequence around (like a clock with m positions)
- **Multiplier (a)**: Scales the current value before adding the increment
- **Increment (c)**: Added to ensure the sequence doesn't get stuck at zero
- **Period**: How many values the generator produces before repeating

</blockquote></details>

Implement the `lcg_keystream` function that generates a stream of bytes using the LCG algorithm.


```python

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
    # TODO: Implement the LCG keystream generator
    #    - Update state using the LCG formula
    #    - Yield the lowest 8 bits of state as a byte
    pass
from w1d1_test import test_lcg_keystream


test_lcg_keystream(lcg_keystream)
```

### Exercise 1.2: Building a Stream Cipher

> **Difficulty**: 🔴🔴⚪⚪⚪
> **Importance**: 🔵🔵🔵🔵⚪
>
> You should spend up to ~10 minutes on this exercise.

Stream ciphers work by XORing the plaintext with a keystream. The encryption process is:
```
ciphertext[i] = plaintext[i] XOR keystream[i]
```

Decryption is identical:
```
plaintext[i] = ciphertext[i] XOR keystream[i]
```

This works because: `(A XOR B) XOR B = A XOR (B XOR B) = A XOR 0 = A`

<details>
<summary>Vocabulary: XOR Operation</summary><blockquote>

- **XOR (Exclusive OR)**: A bitwise operation that outputs 1 when inputs differ and 0 when they're the same. Key properties:
  - `A XOR A = 0` (anything XORed with itself is zero)
  - `A XOR 0 = A` (XORing with zero leaves value unchanged)
  - `A XOR B = B XOR A` (commutative)
  - `(A XOR B) XOR B = A` (self-inverse property - crucial for stream ciphers!)

</blockquote></details>

Implement the `encrypt` and `decrypt` functions using your LCG keystream.


```python


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
    pass
from w1d1_test import test_decrypt


test_decrypt(lcg_decrypt)
from w1d1_test import test_stream_cipher


test_stream_cipher(lcg_keystream, lcg_encrypt, lcg_decrypt)
```

### Stream Cipher Security

Now that you've built a stream cipher, let's explore its security properties and weaknesses.

#### Why LCG is Not Cryptographically Secure

While our LCG-based stream cipher works, it's not secure for cryptographic use:

1. **Predictability**: Given a few outputs, the entire sequence can be predicted - we'll do this in the next exercise!
2. **Short period**: Will repeat after at most 2^32 outputs
3. **Statistical bias**: Even a small amount of bias can be used to decrease the search space for brute-force attacks
4. **State recovery**: The internal state can be recovered from outputs

#### Real Cryptographic Stream Ciphers

Modern stream ciphers like ChaCha20 address these issues:
- Use complex non-linear operations
- Have much larger internal states
- Resist known cryptanalytic attacks
- Pass stringent randomness tests

#### The Importance of Key Reuse

One critical vulnerability in stream ciphers is key reuse. If the same key (seed) is used to encrypt two different messages:

```
C1 = M1 XOR Keystream
C2 = M2 XOR Keystream

Then: C1 XOR C2 = M1 XOR M2
```

This reveals the XOR of the two plaintexts, which can be used to recover both messages!

<details>
<summary>Vocabulary: Key Reuse Attack</summary><blockquote>

- **Two-time pad**: When a one-time pad (or stream cipher key) is used twice - a critical security failure
- **Crib dragging**: A technique to recover plaintexts when you have `M1 XOR M2` by guessing common words
- **Known plaintext attack**: When an attacker knows some plaintext-ciphertext pairs
- **Malleability**: The property that allows an attacker to modify ciphertexts in predictable ways

</blockquote></details>

#### Next Steps

In practice, you would:
1. Use cryptographically secure PRNGs (like those in `secrets` module)
2. Never reuse keys/nonces in stream ciphers
3. Consider authenticated encryption modes
4. Use well-vetted algorithms like ChaCha20 or AES-CTR

Understanding these basic principles helps you appreciate why cryptographic primitives are designed the way they are!

<details>
<summary>Vocabulary: More Cryptography Terms</summary><blockquote>

- **Nonce**: A "number used once" - a value that should never be repeated with the same key. Critical for stream cipher security
- **Authenticated encryption**: Encryption that also provides integrity checking to detect tampering
- **ChaCha20**: A modern stream cipher designed by Daniel Bernstein, used in TLS 1.3
- **AES-CTR**: AES (Advanced Encryption Standard) in Counter mode, which turns the block cipher into a stream cipher
- **Initialization Vector (IV)**: Similar to a nonce, used to ensure same plaintext encrypts differently each time

</blockquote></details>


### Exercise 1.3: Breaking Stream Ciphers with Crib-Dragging

When a stream cipher key is reused, it becomes vulnerable to a **crib-dragging attack**. If we have two ciphertexts encrypted with the same keystream:

```
C1 = M1 XOR K
C2 = M2 XOR K
```

Then: `C1 XOR C2 = M1 XOR M2`

If we guess (or "crib") part of one message, we can recover the corresponding part of the other message!

<details>
<summary>How Crib-Dragging Works</summary><blockquote>

1. We XOR the two ciphertexts to get `M1 XOR M2`
2. We guess a word or phrase that might appear in one message (the "crib")
3. We XOR this crib at different positions in `M1 XOR M2`
4. When we find the right position, we'll see readable text from the other message
5. This reveals parts of both plaintexts, which can help us guess more

</blockquote></details>

### Exercise 1.3a: LCG State Recovery

> **Difficulty**: 🔴🔴🔴⚪⚪
> **Importance**: 🔵🔵🔵🔵⚪
>
> You should spend up to ~15 minutes on this exercise.


First, let's understand how to recover the LCG seed from known keystream bytes.

Implement the `recover_lcg_state` function that recovers the seed from consecutive keystream bytes.


```python


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
    # TODO: Implement LCG state recovery
    #   - brute-force through all possible upper 24 bits - this will let you try all possible starting states
    #   - for each state, check if it produces the correct bytes
    #   - if it does, calculate the seed by rearranging the LCG formula to get a formula for the seed
    pass
```

<details>
<summary>Hints</summary><blockquote>

- loop through each possible upper 24 bits (2^24 possibilities)
- construct state_0 = (upper_24_bits << 8) | keystream_bytes[0]
- check if this state produces the correct subsequent bytes
- if valid, calculate the seed using modular arithmetic
</blockquote></details>


```python
from w1d1_test import test_lcg_state_recovery


test_lcg_state_recovery(lcg_keystream, recover_lcg_state)
```

### Exercise 1.3b: The Crib-Dragging Attack

> **Difficulty**: 🔴🔴🔴🔴⚪
> **Importance**: 🔵🔵🔵🔵🔵
>
> You should spend up to ~20 minutes on this exercise.

Now let's perform a real crib-dragging attack. We have intercepted two messages encrypted with the same key. It looks like the messages are talking about LCGs and stream ciphers, so you can safely assume that the phrase "linear congruential generator" appears in one of them.

Implement the `crib_drag` function that tries a known plaintext fragment at different positions.


```python

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
```

### Exercise 1.3c: Full Message Recovery

> **Difficulty**: 🔴🔴🔴🔴⚪
> **Importance**: 🔵🔵🔵🔵🔵
>
> You should spend up to ~15 minutes on this exercise.

Now that we've found where the crib appears, we can:
1. Recover part of the keystream at that position
2. Find the LCG state that produced those keystream bytes
3. Reverse the LCG to find the original seed
4. Decrypt both messages completely!

The key insight: if we know keystream bytes at position P, we can find the state that
produced them, then reverse the LCG P times to get back to the original seed.

First, implement `recover_seed` that finds the original seed from a known plaintext at a specific position.


```python


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
```

Now implement `recover_messages` that uses `recover_seed` to decrypt both messages.


```python


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
```

### Summary: What We've Learned

Through this crib-dragging attack, we've demonstrated several critical points:

1. **Key Reuse is Fatal**: Using the same keystream to encrypt multiple messages completely breaks the security of a stream cipher.

2. **Known Plaintext is Powerful**: Even knowing a small fragment like "linear congruential generator" allowed us to:
   - Find where it appears in the message
   - Recover part of the keystream
   - Eventually decrypt both entire messages

3. **LCGs are Cryptographically Weak**: We could recover the internal state from just a few output bytes, showing why LCGs should never be used for cryptography.

4. **Real-World Implications**:
   - WEP (the old WiFi security protocol) was broken partly due to key reuse
   - Many amateur cryptographic implementations fail due to PRNG weaknesses
   - This is why modern stream ciphers use nonces to ensure unique keystreams

### Preventing These Attacks

Modern cryptographic practice prevents these attacks by:
- **Never reusing keys**: Use unique keys or nonces for each message
- **Using cryptographic PRNGs**: Like ChaCha20's generator or AES-CTR
- **Making state recovery infeasible**: Using large states and non-linear operations
- **Authenticated encryption**: Adding integrity checks to detect tampering

Remember: Don't roll your own crypto! Use well-vetted libraries like `cryptography` in Python.


### Stretch: Automated Crib-Dragging

Try implementing an automated crib-dragging tool that:
1. Takes a dictionary of common words/phrases (e.g., /usr/dict/words)
2. Tries each one at every position
3. Scores results based on how "readable" the recovered text is
4. Automatically finds the most likely plaintexts

This is how many real cryptanalysis tools work!


```python


def automated_crib_drag(ct1: bytes, ct2: bytes, wordlist: list[str]) -> dict:
    """
    Automated crib-dragging with multiple candidate words.

    Args:
        ct1, ct2: The two ciphertexts
        wordlist: List of potential cribs to try

    Returns:
        Dictionary of findings with confidence scores
    """
    # Left as an exercise for the reader!
    # Hints:
    # - Try each word at each position
    # - Score based on percentage of printable characters
    # - Look for common English letter frequencies
    # - Check for common bigrams like "th", "he", "in"
    pass
```

## 2️⃣ Block Ciphers: Simplified DES

In this section, you will implement a simpler version of the DES (Data Encryption Standard) block cipher, which is a classic example of a Feistel cipher. DES was widely used for data encryption until it was superseded by AES (Advanced Encryption Standard).

### Understanding Feistel Ciphers

Feistel ciphers are a fundamental design structure for many block ciphers, introduced by Horst Feistel at IBM in the early 1970s.
The key innovation of a Feistel network is its elegant approach to creating a reversible encryption function from any arbitrary function.
In a Feistel cipher, the input block is split into two halves (left and right).
Through multiple rounds, the right half is passed through a round function (typically involving the round key) and the output is XORed with the left half.
The halves are then swapped for the next round.
This structure makes it so that decryption uses the exact same algorithm as encryption, just with the round keys applied in reverse order.
The round function itself doesn't need to be reversible, which provides great flexibility in design.
The security of a Feistel cipher comes from using many rounds - typically 16 or more - which creates a complex relationship between the plaintext and ciphertext that resists cryptanalysis.

The Data Encryption Standard (DES) is perhaps the most famous implementation of a Feistel cipher and served as the de facto encryption standard from 1977 until the early 2000s.
DES operates on 64-bit blocks using a 56-bit key (though often represented as 64 bits with parity bits) and performs 16 rounds of encryption.
Each round uses a 48-bit subkey derived from the main key through a process called key scheduling.
The heart of DES is its f-function, which expands the 32-bit half-block to 48 bits, XORs it with the round key, and then passes it through eight S-boxes (substitution boxes) that provide the crucial non-linearity needed for security.
While DES was remarkably resilient to cryptanalysis for decades, its 56-bit key size eventually became vulnerable to brute-force attacks as computing power increased.
This led to Triple DES (3DES) as a stopgap measure, and ultimately to the adoption of AES as the new standard.

![DES image from wikipedia](https://upload.wikimedia.org/wikipedia/commons/2/25/Data_Encription_Standard_Flow_Diagram.svg)

In this exercise, you will implement a simplified version of DES to understand its structure and components, including the key schedule, initial permutation, expansion/permutation, S-boxes, and the Feistel function.
You will also implement 2DES and an attack that demonstrates why doubling the rounds does not double the security.

### DES Components

- **Initial Permutation (IP)**: Rearranges input bits
- **Expansion/Permutation (E/P)**: Expands 4 bits to 8 bits
- **S-boxes**: Non-linear substitution providing confusion
- **P4 Permutation**: Diffuses S-box outputs
- **Key Schedule**: Derives two 8-bit subkeys from the 10-bit main key


```python
import random
from typing import List, Tuple

_params_rng = random.Random(0)
P10 = list(range(10))
_params_rng.shuffle(P10)

_p8_idx = list(range(10))
_params_rng.shuffle(_p8_idx)
P8 = _p8_idx[:8]

IP = list(range(8))
_params_rng.shuffle(IP)
IP_INV = [IP.index(i) for i in range(8)]

EP = [_params_rng.randrange(4) for _ in range(8)]
P4 = list(range(4))
_params_rng.shuffle(P4)

S0 = [[_params_rng.randrange(4) for _ in range(4)] for _ in range(4)]
S1 = [[_params_rng.randrange(4) for _ in range(4)] for _ in range(4)]
```

### Exercise 2.1: Understanding Permutations and Expansions

> **Difficulty**: 🔴🔴⚪⚪⚪
> **Importance**: 🔵🔵🔵🔵🔵
>
> You should spend up to ~15 minutes on this exercise.

Permutations and expansions are fundamental operations in DES. A permutation rearranges bits, while an expansion duplicates some bits to create a larger output.

Implement the `permute` function that applies a permutation table to a value.


```python


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
    # TODO: Implement permutation
    #    - For each position i in the output
    #    - Get the source bit position from table[i]
    #    - Extract that bit from the input
    #    - Place it at position i in the output
    pass
```

<details>
<summary>Hints</summary><blockquote>

Start with `out = 0`, then for each output position:
1. Find which input bit should go there (from the table)
2. Extract that bit from the input
3. OR it into the output at the correct position
</blockquote></details>


```python
from w1d1_test import test_permute_expand


# Run the test
test_permute_expand(permute_expand)
```

### Exercise 2.2: Key Schedule - Generating Subkeys

> **Difficulty**: 🔴🔴🔴⚪⚪
> **Importance**: 🔵🔵🔵🔵⚪
>
> You should spend up to ~20 minutes on this exercise.

The key schedule derives two 8-bit subkeys from the 10-bit main key. This process involves:
1. Initial permutation (P10)
2. Splitting into two 5-bit halves
3. Left circular shifts
4. Selection permutation (P8)

The circular shift is crucial - it ensures all key bits influence both subkeys.

Implement the key schedule function.


```python


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
```

### Exercise 2.3: The Feistel Function (fk)

> **Difficulty**: 🔴🔴🔴🔴⚪
> **Importance**: 🔵🔵🔵🔵🔵
>
> You should spend up to ~25 minutes on this exercise.

The heart of DES is the Feistel function, which combines expansion, S-box substitution, and permutation. This function provides both confusion (S-boxes) and diffusion (permutations).

The Feistel function processes the right half of the data:
1. Expand 4 bits to 8 bits using E/P
2. XOR with the round subkey
3. Split into two 4-bit halves
4. Apply S-box substitution to each half
5. Combine and permute with P4
6. XOR result with the left half

Implement the S-box lookup and Feistel function.


```python


def sbox_lookup(sbox: List[List[int]], bits: int) -> int:
    """
    Look up a value in an S-box.

    DES S-boxes are 4x4 tables accessed by:
    - Row: bit 0 (MSB) and bit 3 (LSB) form a 2-bit row index
    - Column: bits 1 and 2 form a 2-bit column index

    Args:
        sbox: 4x4 table of 2-bit values
        bits: 4-bit input (only lower 4 bits used)

    Returns:
        2-bit output from S-box

    Example:
        For input 0b1010:
        - Row = b0,b3 = 1,0 = 2
        - Col = b1,b2 = 0,1 = 1
        - Output = sbox[2][1]
    """
    # TODO: Implement S-box lookup
    pass
from w1d1_test import test_sbox_lookup


test_sbox_lookup(sbox_lookup, S0, S1)
# %%


def fk(
    left: int, right: int, subkey: int, ep: List[int], s0: List[List[int]], s1: List[List[int]], p4: List[int]
) -> Tuple[int, int]:
    """
    Apply the Feistel function to one round of DES.

    Process:
    1. Expand right half from 4 to 8 bits using E/P
    2. XOR with subkey
    3. Split into two 4-bit halves
    4. Apply S0 to left half, S1 to right half
    5. Combine S-box outputs and permute with P4
    6. XOR result with left half

    Args:
        left: 4-bit left half
        right: 4-bit right half
        subkey: 8-bit round key
        ep: Expansion permutation table (4 → 8 bits)
        s0: First S-box (4x4)
        s1: Second S-box (4x4)
        p4: Final permutation (4 → 4 bits)

    Returns:
        Tuple of (new_left, right) - right is unchanged
    """
    # TODO: Implement Feistel function
    #    - Expand right using E/P
    #    - XOR with subkey
    #    - Apply S-boxes to each half
    #    - Combine outputs and apply P4
    #    - XOR with left to get new left
    pass
from w1d1_test import test_feistel


# Run the test
test_feistel(sbox_lookup, fk, EP, S0, S1, P4)
```

### Exercise 2.4: Complete DES Encryption

> **Difficulty**: 🔴🔴🔴⚪⚪
> **Importance**: 🔵🔵🔵🔵🔵
>
> You should spend up to ~20 minutes on this exercise.

Now let's put it all together! DES encryption consists of:
1. Initial permutation (IP)
2. First Feistel round with K1
3. Swap halves
4. Second Feistel round with K2
5. Final permutation (IP⁻¹)

Remember - in feistel networks, decryption uses the same algorithm with subkeys in reverse order!

Implement the complete DES encryption/decryption for a single byte.


```python


def encrypt_byte(
    byte: int,
    k1: int,
    k2: int,
    ip: List[int],
    ip_inv: List[int],
    ep: List[int],
    s0: List[List[int]],
    s1: List[List[int]],
    p4: List[int],
) -> int:
    """
    Encrypt or decrypt a single byte using DES.

    For encryption: use (k1, k2)
    For decryption: use (k2, k1) - reversed order!

    Process:
    1. Apply initial permutation (IP)
    2. Split into 4-bit halves
    3. Apply fk with first key
    4. Swap halves
    5. Apply fk with second key
    6. Combine halves and apply IP⁻¹

    Args:
        byte: 8-bit value to process
        k1: First subkey (8 bits)
        k2: Second subkey (8 bits)
        ip: Initial permutation table
        ip_inv: Inverse initial permutation table
        ep: Expansion permutation for fk
        s0, s1: S-boxes for fk
        p4: Permutation for fk

    Returns:
        8-bit processed value
    """
    # TODO: Implement DES encryption/decryption
    #    - Apply IP
    #    - Two rounds with swap in between
    #    - Apply IP⁻¹
    #    - Same function for encrypt/decrypt!
    pass


def des_encrypt(key: int, plaintext: bytes) -> bytes:
    """Encrypt bytes using DES"""
    k1, k2 = key_schedule(key, P10, P8)
    return bytes(encrypt_byte(b, k1, k2, IP, IP_INV, EP, S0, S1, P4) for b in plaintext)


def des_decrypt(key: int, ciphertext: bytes) -> bytes:
    """Decrypt bytes using DES."""
    k1, k2 = key_schedule(key, P10, P8)
    # Note: reversed key order for decryption!
    return bytes(encrypt_byte(b, k2, k1, IP, IP_INV, EP, S0, S1, P4) for b in ciphertext)
from w1d1_test import test_des_complete


# Run the test
test_des_complete(encrypt_byte, des_encrypt, des_decrypt, key_schedule, P10, P8, IP, IP_INV, EP, S0, S1, P4)
```

### Exercise 2.5: Meet-in-the-Middle Attack on Double DES

> **Difficulty**: 🔴🔴🔴🔴🔴
> **Importance**: 🔵🔵🔵🔵🔵
>
> You should spend up to ~30 minutes on this exercise.

When DES is applied twice with different keys (Double DES), you might expect 2²⁰ = 1,048,576 possible key combinations. However, the meet-in-the-middle attack reduces this to about 2¹¹ = 2,048 operations!

The attack works by:
1. Encrypting the plaintext with all possible first keys
2. Decrypting the ciphertext with all possible second keys
3. Finding where these meet in the middle

This demonstrates why simply applying a cipher multiple times doesn't necessarily multiply the security.

Implement the meet-in-the-middle attack on Double DES.


```python


def double_encrypt(key1: int, key2: int, plaintext: bytes) -> bytes:
    """Encrypt twice with different keys."""
    temp = des_encrypt(key1, plaintext)
    return des_encrypt(key2, temp)


def double_decrypt(key1: int, key2: int, ciphertext: bytes) -> bytes:
    """Decrypt twice with different keys (reverse order)."""
    temp = des_decrypt(key2, ciphertext)
    return des_decrypt(key1, temp)


def meet_in_the_middle_attack(plaintext: bytes, ciphertext: bytes) -> List[Tuple[int, int]]:
    """
    Find all key pairs (k1, k2) such that:
    double_encrypt(k1, k2, plaintext) == ciphertext

    Strategy:
    1. Build table: for each k1, compute encrypt(k1, plaintext)
    2. For each k2, compute decrypt(k2, ciphertext)
    3. If decrypt(k2, ciphertext) is in our table, we found a match!

    Args:
        plaintext: Known plaintext
        ciphertext: Corresponding ciphertext from double encryption

    Returns:
        List of (key1, key2) pairs that work
    """
    # TODO: Implement meet-in-the-middle attack
    #    - Build table of all encrypt(k1, plaintext)
    #    - For each k2, check if decrypt(k2, ciphertext) is in table
    #    - Return all matching (k1, k2) pairs
    pass
```

<details>
<summary>Hint 1: Building the forward table</summary><blockquote>

Use a dictionary to map intermediate values to keys:
```python
forward_table = {}
for k1 in range(1024):
    intermediate = encrypt(k1, plaintext)
    # Store k1 values that produce this intermediate
```

Remember to handle bytes → int conversion for dict keys.
</blockquote></details>


```python
from w1d1_test import test_meet_in_the_middle


# Run the test
test_meet_in_the_middle(meet_in_the_middle_attack, double_encrypt)
```

## 3️⃣ Block Ciphers: Substitution-Permutation Networks

In this section, you'll implement a simplified block cipher based on the Substitution-Permutation Network (SPN) structure. You will continue on the work started in the previous section, where you learned about S-boxes and P-boxes, and build AES, which is the most widely used block cipher today. This exercise will help you understand the fundamental concepts of block ciphers, including confusion, diffusion, and key scheduling.

### Understanding Substitution-Permutation Networks

The Advanced Encryption Standard (AES) is a symmetric block cipher that replaced DES as the encryption standard in 2001.
Unlike DES's Feistel structure, AES uses a substitution-permutation network (SPN) that operates on the entire data block in each round rather than just half.
AES processes data in 128-bit blocks and supports three key sizes: 128, 192, and 256 bits, with 10, 12, and 14 rounds respectively.
Each round (except the last) consists of four operations: SubBytes (byte substitution using S-boxes), ShiftRows (cyclical shifting of rows), MixColumns (mixing data within columns), and AddRoundKey (XORing with the round key).
The design philosophy emphasizes algebraic simplicity and efficiency, with operations carefully chosen to provide strong diffusion and confusion while being implementable in both hardware and software.

![Wikipedia image for AES](https://upload.wikimedia.org/wikipedia/commons/5/50/AES_%28Rijndael%29_Round_Function.png)

### Key Properties of Secure Block Ciphers

1. **Confusion**: The relationship between key and ciphertext should be complex and non-linear
2. **Diffusion**: Each bit of plaintext should affect many bits of ciphertext
3. **Avalanche effect**: Small changes in input should cause large changes in output
4. **Key size**: Must be large enough to prevent brute-force attacks (128+ bits)
5. **Block size**: Should be large enough to prevent birthday attacks (128+ bits)

<details>
<summary>Vocabulary: Cryptographic Terms</summary><blockquote>

- **S-box (Substitution box)**: A non-linear transformation that substitutes input bits with output bits, providing confusion
- **P-box (Permutation box)**: A transformation that rearranges bit positions, providing diffusion
- **SPN (Substitution-Permutation Network)**: A cipher structure alternating substitution and permutation layers
- **Round key**: A subkey derived from the main key, used in each round of encryption
- **Confusion**: Making the relationship between key and ciphertext as complex as possible
- **Diffusion**: Spreading the influence of plaintext bits throughout the ciphertext
- **Block cipher modes**: Methods for encrypting data larger than one block (ECB, CBC, CTR, etc.)

</blockquote></details>


### Exercise 3.1: Implementing S-box Substitution

> **Difficulty**: 🔴🔴⚪⚪⚪
> **Importance**: 🔵🔵🔵🔵⚪
>
> You should spend up to ~15 minutes on this exercise.

S-boxes (Substitution boxes) are a fundamental component of block ciphers that provide non-linearity and confusion. They work by substituting small blocks of bits according to a predefined lookup table.

In our toy cipher, we use 4-bit S-boxes (16 possible inputs → 16 outputs). The 16-bit block is divided into four 4-bit nibbles, and each nibble is substituted independently.

<details>
<summary>Vocabulary: S-box Terms</summary><blockquote>

- **Nibble**: A 4-bit value (half a byte), can represent values 0-15
- **Non-linearity**: The property that output bits don't have a simple linear relationship with input bits
- **Lookup table**: An array where the index is the input and the value is the output
- **Bit extraction**: Using shifts (>>) and masks (&) to isolate specific bits
- **Bit packing**: Using OR (|) and shifts (<<) to combine bits into a larger value

</blockquote></details>

Implement the `substitute` function that applies S-box substitution to a 16-bit value.


```python

from typing import List
import random


def _generate_sbox(seed: int = 1):
    rng = random.Random(seed)
    sbox = list(range(16))
    rng.shuffle(sbox)
    inv = [0] * 16
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


SBOX, INV_SBOX = _generate_sbox()


def substitute(x: int, sbox: List[int]) -> int:
    """
    Apply S-box substitution to a 16-bit value.

    The 16-bit input is divided into four 4-bit nibbles.
    Each nibble is substituted using the provided S-box.

    Args:
        x: 16-bit integer to substitute
        sbox: List of 16 integers (0-15) defining the substitution

    Returns:
        16-bit integer after substitution
    """
    # TODO: Implement S-box substitution
    #    - Extract each 4-bit nibble from x
    #    - Look up the substitution for each nibble in sbox
    #    - Combine the substituted nibbles into the output
    pass
```

<details>
<summary>Hints</summary><blockquote>

1. Start with a variable `out` initialized to 0.
2. For each nibble (0 to 3):
    - Extract the nibble
    - Use the S-box to find the substituted value
    - or the substituted value into `out` at the correct position
3. Return the final `out` value.
</blockquote></details>


```python
from w1d1_test import test_substitute


# Run the test
test_substitute(substitute, SBOX)
```

### Exercise 3.2: Implementing P-box Permutation

> **Difficulty**: 🔴🔴🔴⚪⚪
> **Importance**: 🔵🔵🔵🔵⚪
>
> You should spend up to ~20 minutes on this exercise.

P-boxes (Permutation boxes) provide diffusion by rearranging the bit positions. While S-boxes work on small chunks, P-boxes work on the entire block, ensuring that changes in one part affect other parts.

In our 16-bit cipher, the P-box is a list of 16 values that defines how bits are rearranged.

<details>
<summary>Vocabulary: P-box Terms</summary><blockquote>

- **Bit position**: The location of a bit in a binary number (0 = rightmost)
- **Permutation**: A rearrangement where each input has exactly one output
- **Diffusion**: The property that input changes spread throughout the output
- **Bit extraction**: Reading a single bit from a specific position
- **Bit placement**: Setting a single bit at a specific position

</blockquote></details>

Implement the `permute` function that applies P-box permutation to a 16-bit value.


```python


def _generate_pbox(seed: int = 2):
    rng = random.Random(seed)
    pbox = list(range(16))
    rng.shuffle(pbox)
    inv = [0] * 16
    for i, p in enumerate(pbox):
        inv[p] = i
    return pbox, inv


PBOX, INV_PBOX = _generate_pbox()


def permute(x: int, pbox: List[int]) -> int:
    """
    Apply P-box permutation to a 16-bit value.

    For each output bit position i, take the bit from input position pbox[i].

    Args:
        x: 16-bit integer to permute
        pbox: List of 16 integers (0-15) defining the permutation
              pbox[i] = j means output bit i comes from input bit j

    Returns:
        16-bit integer after permutation
    """
    # TODO: Implement P-box permutation
    #    - For each output position i (0 to 15)
    #    - Get the input bit from position pbox[i]
    #    - Place it at output position i
    pass
```

<details>
<summary>Hints</summary><blockquote>

1. Start with a variable `out` initialized to 0.
2. For each output position `i` (0 to 15):
    - Get the input bit from position `pbox[i]`
    - Shift it to the correct position in `out`
3. Return the final `out` value.
</blockquote></details>


```python
from w1d1_test import test_permute


# Run the test
test_permute(permute, PBOX)
```

### Exercise 3.3: Building the Complete Block Cipher

> **Difficulty**: 🔴🔴🔴⚪⚪
> **Importance**: 🔵🔵🔵🔵🔵
>
> You should spend up to ~20 minutes on this exercise.

Now that you understand S-boxes and P-boxes, let's combine them to build a complete Substitution-Permutation Network (SPN). Our toy cipher uses two rounds of substitution and permutation, with round keys XORed at each stage:

```
Plaintext
    ↓
   XOR (key[0])
    ↓
  S-box
    ↓
  P-box
    ↓
   XOR (key[1])
    ↓
  S-box
    ↓
  P-box
    ↓
   XOR (key[2])
    ↓
Ciphertext
```

<details>
<summary>Vocabulary: Block Cipher Terms</summary><blockquote>

- **Round**: One complete cycle of substitution, permutation, and key mixing
- **Round key**: A subkey derived from the main key, used in each round
- **Key schedule**: The algorithm that generates round keys from the main key
- **XOR (⊕)**: Exclusive OR operation, used for mixing keys with data
- **Block**: A fixed-size chunk of data (16 bits in our toy cipher)

</blockquote></details>

Implement the `encrypt_block` and `decrypt_block` functions that perform the full encryption/decryption process.


```python


def round_keys(key: int) -> List[int]:
    """Generate round keys from the main key."""
    import random

    rng = random.Random(key)
    return [rng.randrange(0, 1 << 16) for _ in range(3)]


def encrypt_block(block: int, keys: List[int], sbox: List[int], pbox: List[int]) -> int:
    """
    Encrypt a single 16-bit block using the SPN cipher.

    The cipher consists of:
    1. XOR with key[0]
    2. S-box substitution
    3. P-box permutation
    4. XOR with key[1]
    5. S-box substitution
    6. P-box permutation
    7. XOR with key[2]

    Args:
        block: 16-bit integer to encrypt
        keys: List of 3 round keys
        sbox: S-box for substitution
        pbox: P-box for permutation

    Returns:
        16-bit encrypted block
    """
    # TODO: Implement the encryption algorithm
    #    - Start with XOR of block and keys[0]
    #    - Apply S-box substitution and P-box permutation
    #    - XOR with keys[1]
    #    - Apply S-box substitution and P-box permutation again
    #    - End with XOR of keys[2]
    pass


def decrypt_block(block: int, keys: List[int], inv_sbox: List[int], inv_pbox: List[int]) -> int:
    """
    Decrypt a single 16-bit block using the SPN cipher.

    Decryption reverses the encryption process:
    1. XOR with key[2]
    2. Inverse P-box permutation
    3. Inverse S-box substitution
    4. XOR with key[1]
    5. Inverse P-box permutation
    6. Inverse S-box substitution
    7. XOR with key[0]

    Args:
        block: 16-bit integer to decrypt
        keys: List of 3 round keys (same as encryption)
        inv_sbox: Inverse S-box for substitution
        inv_pbox: Inverse P-box for permutation

    Returns:
        16-bit decrypted block
    """
    # TODO: Implement the decryption algorithm
    #    - Reverse the encryption steps
    #    - Use inverse S-box and P-box
    #    - Apply keys in reverse order
    pass
from w1d1_test import test_block_cipher


# Run the test
test_block_cipher(encrypt_block, decrypt_block, round_keys, SBOX, PBOX, INV_SBOX, INV_PBOX)
```

### Exercise 3.4: Implementing ECB Mode

> **Difficulty**: 🔴🔴🔴🔴⚪
> **Importance**: 🔵🔵🔵⚪⚪
>
> You should spend up to ~25 minutes on this exercise.

Electronic Codebook (ECB) mode is the simplest block cipher mode - it encrypts each block independently. While ECB has security weaknesses (it doesn't hide patterns), it's a good starting point for understanding block cipher modes.

Our implementation needs to:
1. Split the message into 16-bit blocks (2 bytes each)
2. Encrypt each block independently
3. Handle padding for the last block if needed

<details>
<summary>Vocabulary: ECB Mode Terms</summary><blockquote>

- **Block cipher mode**: A method for encrypting data larger than one block
- **ECB (Electronic Codebook)**: Mode where each block is encrypted independently
- **Padding**: Adding bytes to make the message length a multiple of the block size
- **Big-endian**: Most significant byte first (used in our implementation)

</blockquote></details>

Implement the `encrypt` and `decrypt` functions that handle full messages using ECB mode.


```python


def aes_encrypt(key: int, plaintext: bytes, sbox: List[int], pbox: List[int]) -> bytes:
    """
    Encrypt a message using ECB mode with our 16-bit block cipher.

    Process:
    1. Generate round keys from the main key
    2. Pad the message if necessary (with null bytes)
    3. Split into 2-byte blocks
    4. Encrypt each block
    5. Concatenate results (truncate padding if needed)

    Args:
        key: Encryption key (used as seed for round key generation)
        plaintext: Bytes to encrypt
        sbox: S-box for substitution
        pbox: P-box for permutation

    Returns:
        Encrypted bytes (same length as plaintext)
    """
    # TODO: Implement ECB encryption
    #    - Generate round keys using round_keys()
    #    - Handle padding if message length is odd
    #    - Process each 2-byte block
    #    - Return result truncated to original length
    pass


def aes_decrypt(key: int, ciphertext: bytes, inv_sbox: List[int], inv_pbox: List[int]) -> bytes:
    """
    Decrypt a message using ECB mode with our 16-bit block cipher.

    Process:
    1. Generate round keys from the main key
    2. Pad the ciphertext if necessary
    3. Split into 2-byte blocks
    4. Decrypt each block
    5. Concatenate results (truncate padding if needed)

    Args:
        key: Decryption key (same as encryption key)
        ciphertext: Bytes to decrypt
        inv_sbox: Inverse S-box for substitution
        inv_pbox: Inverse P-box for permutation

    Returns:
        Decrypted bytes (same length as ciphertext)
    """
    # TODO: Implement ECB decryption
    #    - Similar to encryption but use decrypt_block
    #    - Remember to use inverse S-box and P-box
    pass
from w1d1_test import test_ecb_mode


# Run the test
test_ecb_mode(aes_encrypt, aes_decrypt, SBOX, PBOX, INV_SBOX, INV_PBOX)
```

## Further reading
If you'd like to learn more about real-world attacks, you can read, e.g., about [attacks on the RC4 stream cipher](https://en.wikipedia.org/wiki/RC4#Security). This algorithm was widely used in protocols like TLS and WEP, but it has several vulnerabilities that make it insecure for modern use. A notable attack on RC4 is the [Fluhrer, Mantin, and Shamir attack](https://en.wikipedia.org/wiki/Fluhrer,_Mantin_and_Shamir_attack), which exploits the surprising finding thatthe statistics for the first few bytes of output keystream are strongly non-random.



