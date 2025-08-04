# %%
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
# %%
from w1d1_test import test_permute_expand

"""
Apply a permutation table to rearrange bits. 
Note that the bits are numbered from left to right (MSB first).

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

To expand the number, make the table larger than the number of digits in
the binary number. 
"""


# %%
def permute_expand(value: int, table: List[int], in_width: int) -> int:
    # Convert to binary string without '0b' prefix, padded to in_width
    binary_str_input = bin(value)[2:]

    binary_str_output = ""

    for source_pos in table:
        binary_str_output += binary_str_input[source_pos]

    # Convert binary string back to integer
    return int(binary_str_output, 2)


test_permute_expand(permute_expand)

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
    P10: Initial permutation table (10 → 10 bits)
    p8: Selection permutation table (10 → 8 bits)

Returns:
    Tuple of (K1, K2) - the two 8-bit subkeys

Feistel cipher:

1 round (typically do 16):
    - split block into two halves 
    - right half is passed to a round function
    - XOR output with left half
    - swap halves

DES is an implementation of Feistel cipher (16 rounds of encryption):

- 1 block = 64 bits. 
- key =  56 bits (though often represented as 64 bits with parity bits)
- subkey = 48 bits (derived from main key)
- f-function: 
    - expands 32 into 48 bits
    - XORs with the round key
    - passes it through 8 s-boxes (substitution boces)

steps of DES:

1. permuation of bits
2. expands 4 bits into 8 bits
3. s boxes
4. p4 permutation
5. key schedule 

"""


# %%
def key_schedule(key: int, p10: List[int], p8: List[int]) -> Tuple[int, int]:
    # TODO: Implement key schedule
    #    -
    #    - Split into 5-bit halves
    #    - Generate K1
    #       - Left shift both halves by 1 (LS-1)
    #       - Combine and apply P8
    #    - Generate K2
    #       - Left shift both halves by 2 (LS-2, for total LS-3)
    #       - Combine and apply P8
    #    - you might want to implement left_shift as a helper function
    #       - for example, left_shift 0b10101 by 1 gives 0b01011

    # Apply P10 permutation - permute a 10 digit binary number
    num = bin(permute_expand(key, p10, 10))[2:]

    firsthalf = num[0:5]
    secondhalf = num[5:]

    def circ_left_shift(value: int, n: int, width: int) -> int:
        n %= width
        mask = (1 << width) - 1
        return ((value << n) & mask) | (value >> (width - n))

    # generating k1
    firsthalf = circ_left_shift(firsthalf, 1, 5)
    secondhalf = circ_left_shift(secondhalf, 1, 5)
    k1 = permute_expand(firsthalf << 5 | secondhalf, p8, 10)
    # generating k2
    firsthalf = circ_left_shift(firsthalf, 2, 5)
    secondhalf = circ_left_shift(secondhalf, 2, 5)
    k2 = permute_expand(firsthalf << 5 | secondhalf, p8, 10)
    return [k1, k2]

    # Split into 5-bit halves


from w1d1_test import test_key_schedule

test_key_schedule(key_schedule, P10, P8)
