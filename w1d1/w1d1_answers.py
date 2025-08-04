from typing import List, Tuple
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
    p10: Initial permutation table (10 → 10 bits)
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
    

    # Apply P10 permutation - permute a 10 digit binary number
    num = permute_expand(key, p10, 10)

    # Split into 5-bit halves
    first_half, second_half = num[]

from w1d1_test import test_key_schedule
