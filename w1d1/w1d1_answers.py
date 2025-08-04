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
    # TODO: Implement the LCG keystream generator
    #    - Update state using the LCG formula
    #    - Yield the lowest 8 bits of state as a byte
    current_state = seed
    a = 1664525
    c= 1013904223
    m = 2**32
    while True:
        next_state = (a * current_state + c) % m
        current_state = next_state
        yield next_state & 0xFF

from w1d1_test import test_lcg_keystream


test_lcg_keystream(lcg_keystream)
# %%
