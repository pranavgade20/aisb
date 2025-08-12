# %%
def exploit_basic_overflow() -> str:
    """
    Create an exploit string that overflows the password buffer
    and overwrites the 'authorized' variable to bypass authentication.

    Hint: The password buffer is 16 bytes, and 'authorized' is right after it.
    What happens if we write more than 16 bytes?

    Returns:
        The exploit string that will grant access
    """
    # TODO: Create an exploit string that:
    #   1. Fills the 16-byte password buffer
    #   2. Overwrites the 'authorized' variable with a non-zero value
    #   3. Remember to add a newline at the end
    return "aasfjaskdjfkajlfadjgkljalgja"


from w2d1_re_test import test_basic_overflow

test_basic_overflow(exploit_basic_overflow)

# %%


def find_password_in_binary() -> str:
    """
    Find the hardcoded password in the first.c binary.

    Hint: Try running: strings first | grep -E '^[a-z0-9]{6,}$'
    Or look for the strcmp() call in the decompiled code.

    Returns:
        The password found in the binary
    """
    # TODO: Find the hardcoded password
    # Try: `strings first | grep -v printf`
    return "secret123"


from w2d1_re_test import test_password_extraction


test_password_extraction(find_password_in_binary)
# %%
