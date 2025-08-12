# Allow imports from parent directory
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import struct
import subprocess
import sys
from typing import Callable, Optional, Tuple


def check_binary_protections(binary_path: str) -> dict:
    """
    Check which security protections are enabled on a binary.

    Args:
        binary_path: Path to the binary to check

    Returns:
        Dictionary of protection_name: enabled (bool)
    """
    if "SOLUTION":
        protections = {"NX": False, "PIE": False, "Stack Canary": False, "FORTIFY": False, "RELRO": False}

        # Check with checksec or manually
        # For simplicity, we'll check readelf output

        # Check NX bit
        cmd = f"readelf -l {binary_path} | grep GNU_STACK"
        result = exec_sh(cmd)
        if result.stdout and "RW" in result.stdout and "RWE" not in result.stdout:
            protections["NX"] = True

        # Check PIE
        cmd = f"readelf -h {binary_path} | grep 'Type:'"
        result = exec_sh(cmd)
        if result.stdout and "DYN" in result.stdout:
            protections["PIE"] = True

        # Check for stack canary
        cmd = f"objdump -d {binary_path} | grep -E '__stack_chk_fail|%(fs:0x28)|%(gs:0x14)'"
        result = exec_sh(cmd)
        if result.stdout:
            protections["Stack Canary"] = True

        # Check FORTIFY_SOURCE
        cmd = f"strings {binary_path} | grep -E '_chk@|__fortify'"
        result = exec_sh(cmd)
        if result.stdout:
            protections["FORTIFY"] = True

        # Check RELRO
        cmd = f"readelf -d {binary_path} | grep BIND_NOW"
        result = exec_sh(cmd)
        if result.stdout:
            protections["RELRO"] = True

        return protections
    else:
        # TODO: Implement protection checking
        # Use readelf, objdump, or checksec to identify protections
        pass


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


def test_basic_overflow(exploit_basic_overflow: Callable):
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
        sys.exit(1)


def test_password_extraction(find_password_in_binary: Callable):
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
