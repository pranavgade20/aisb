# Allow imports from parent directory
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import subprocess
import struct
import sys
from typing import Optional, Tuple


# from w2d1_re_answers import compile_vulnerable_binary
def exec_sh(command: str, timeout: Optional[int] = 30, check_retcode: bool = True) -> subprocess.CompletedProcess:
    """Execute a shell command and return the result."""
    return subprocess.run(command, shell=True, capture_output=True, text=True, check=False, timeout=timeout)


def compile_vulnerable_binary(source_file: str, output_file: str, extra_flags: str = "") -> bool:
    """Compile a C program with security features disabled for educational purposes."""
    flags = "-fno-stack-protector -z execstack -no-pie -g"
    cmd = f"gcc {flags} {extra_flags} -o {output_file} {source_file}"
    result = exec_sh(cmd)
    return result.returncode == 0


def test_basic_overflow(exploit_basic_overflow: callable):
    """Test the basic buffer overflow exploit."""
    print("Testing basic buffer overflow...")

    # Compile the vulnerable program
    if not compile_vulnerable_binary("first.c", "first"):
        print("Failed to compile first.c")
        return False

    # Run the exploit
    exploit = exploit_basic_overflow()
    proc = subprocess.Popen(
        [" ./first"], shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    stdout, stderr = proc.communicate(input=exploit)

    # Check if we got the flag
    if "Flag: AISB{woo}" in stdout:
        print("✓ Exploit successful! Got the flag!")
        print(f"Exploit string length: {len(exploit.strip())} bytes")
    else:
        print("✗ Exploit failed. Output:")
        print(stdout)
        exit(1)


def test_advanced_overflow(exploit_basic_overflow: callable):
    """Test the basic buffer overflow exploit."""
    print("Testing basic buffer overflow...")

    # Compile the vulnerable program
    if not compile_vulnerable_binary("second.c", "second"):
        print("Failed to compile second.c")
        return False

    # Run the exploit
    exploit = exploit_basic_overflow()
    proc = subprocess.Popen(
        [" ./second"], shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    stdout, stderr = proc.communicate(input=exploit)

    # Check if we got the flag
    if "Flag: AISB{woo}" in stdout:
        print("✓ Exploit successful! Got the flag!")
        print(f"Exploit string length: {len(exploit.strip())} bytes")
    else:
        print("✗ Exploit failed. Output:")
        print(stdout)
        exit(1)

def test_password_extraction(find_password_in_binary: callable):
    """Test password extraction from binary."""
    print("\nTesting password extraction...")

    password = find_password_in_binary()

    proc = subprocess.Popen(
        [" ./first"], shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    stdout, stderr = proc.communicate(input=password + "\n")

    if "Password correct!" in stdout and "Flag: AISB{woo}" in stdout:
        print(f"✓ Found the password: '{password}'")
        return True
    else:
        print("✗ Password incorrect")
        exit(1)


def test_shellcode_basics():
    """Test basic shellcode creation."""
    print("\nTesting shellcode exploit creation...")

    try:
        exploit = create_shellcode_exploit()
        print(f"✓ Created shellcode exploit: {len(exploit)} bytes")
        print("Exploit structure:")
        print("  - NOP sled: " + str(exploit.count(b"\\x90")) + " bytes")
        print("  - Contains syscall: " + str(b"\x0f\x05" in exploit))
        return True
    except Exception as e:
        print(f"✗ Failed to create exploit: {e}")
        return False


def test_protection_checking():
    """Test binary protection checking."""
    print("\nTesting protection checking...")

    # First compile with protections enabled
    exec_sh(" gcc -o first_protected first.c")

    # Then compile without protections
    exec_sh(" gcc -fno-stack-protector -z execstack -no-pie -o first_vulnerable first.c")

    protected = check_binary_protections("first_protected")
    vulnerable = check_binary_protections("first_vulnerable")

    print("Protected binary:")
    for prot, enabled in protected.items():
        print(f"  {prot}: {'✓' if enabled else '✗'}")

    print("\nVulnerable binary:")
    for prot, enabled in vulnerable.items():
        print(f"  {prot}: {'✓' if enabled else '✗'}")

    # At least NX should be different
    if protected.get("NX", False) != vulnerable.get("NX", True):
        print("\n✓ Successfully identified protection differences")
        return True
    else:
        print("\n✗ Could not identify protection differences")
        return False
