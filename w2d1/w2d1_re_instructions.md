
# W2D1 (stretch) - Reverse Engineering: Buffer Overflow Exploitation

Welcome to the reverse engineering module! Today we'll explore one of the most fundamental vulnerabilities in computer security: buffer overflows. You'll learn how programs manage memory, how attackers can exploit poor memory management, and how to defend against these attacks.

## Prerequisites
- Basic understanding of C programming
- Familiarity with hexadecimal notation
- Access to Ghidra (for binary analysis)
- GCC

## Learning Objectives
By the end of this module, you'll be able to:
1. Identify buffer overflow vulnerabilities in binary code
2. Exploit basic stack-based buffer overflows
3. Overwrite return addresses to control program flow
4. Understand modern security mitigations

Let's start by setting up our helper functions and understanding the tools we'll use.

Copy these functions to your solutions file:


```python


import subprocess
import struct
import sys
from typing import Optional, Tuple, Callable


def exec_sh(command: str, timeout: Optional[int] = 30) -> subprocess.CompletedProcess:
    """Execute a shell command and return the result."""
    return subprocess.run(command, shell=True, capture_output=True, text=True, check=False, timeout=timeout)

def compile_vulnerable_binary(source_file: str, output_file: str, extra_flags: str = "") -> bool:
    def exec_sh(command: str, timeout: Optional[int] = 30) -> subprocess.CompletedProcess:
        """Execute a shell command and return the result."""
        return subprocess.run(command, shell=True, capture_output=True, text=True, check=False, timeout=timeout)

    """Compile a C program with security features disabled for educational purposes."""
    flags = "-fno-stack-protector -z execstack -no-pie -g"
    cmd = f"gcc {flags} {extra_flags} -o {output_file} {source_file}"
    result = exec_sh(cmd)
    return result.returncode == 0


def hex_dump(data: bytes, start_address: int = 0) -> str:
    """Create a hex dump of binary data."""
    lines = []
    for i in range(0, len(data), 16):
        hex_part = ' '.join(f'{b:02x}' for b in data[i:i + 16])
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data[i:i + 16])
        lines.append(f"{start_address + i:08x}: {hex_part:<48} |{ascii_part}|")
    return '\n'.join(lines)
```

## Exercise 1: Understanding Stack Layout and Buffer Overflows

Before we start exploiting, let's understand what happens in memory when a program runs.

<details>
<summary>Vocabulary: Memory Layout</summary><blockquote>

- **Stack**: Memory region that grows downward (high to low addresses) used for function calls, local variables, and return addresses
- **Buffer**: A contiguous block of memory used to store data (like arrays)
- **Return Address**: The memory address where execution continues after a function returns
- **Stack Frame**: The portion of the stack used by a single function call
- **gets()**: A dangerous C function that reads input without bounds checking (deprecated!)

</blockquote></details>

When a function is called:
1. Arguments are pushed onto the stack
2. Return address is saved
3. Previous frame pointer is saved
4. Local variables are allocated

Here's our first vulnerable program (first.c):
```c
char password[16];    // 16-byte buffer
int authorized = 0;   // 4-byte integer
gets(password);       // DANGEROUS: No bounds checking!
```

The stack layout looks like this:
```
[Higher addresses]
├─────────────────┤
│  Return address │
├─────────────────┤
│  Saved EBP      │
├─────────────────┤
│  authorized     │ <- We want to overwrite this!
├─────────────────┤
│  password[16]   │ <- Our input goes here
├─────────────────┤
[Lower addresses]
```

### Exercise 1.1: Ghidra Analysis

> **Difficulty**: 🔴⚪⚪⚪⚪
> **Importance**: 🔵🔵🔵⚪⚪
>
> You should spend up to ~30 minutes on this exercise.

#### Step 1: Setup

1. **Compile the vulnerable binary**:
   ```bash
   gcc -fno-stack-protector -z execstack -no-pie -g first.c -o first
   ```
   If you don't have gcc installed, you can install it with `sudo apt install build-essential`.

2. **Launch Ghidra**:
   - Run `ghidraRun` (or `./ghidra` depending on your installation)
   - Create a new project: File → New Project → Non-Shared Project
   - Name it "BufferOverflowLab"

3. **Import the binary**:
   - File → Import File → Select `first`
   - Format should auto-detect as "ELF"
   - Click "OK" and accept default options
   - Double-click the imported file to open in CodeBrowser

#### Step 2: Initial Analysis

4. **Run auto-analysis**:
   - When prompted "Analyze?", click "Yes"
   - Keep all default analyzers checked
   - Click "Analyze"
   - Wait for the analysis to complete

5. **Navigate the interface**:
   - **Symbol Tree** (left): Shows all functions, labels, and imports
   - **Listing** (center): Assembly code view
   - **Decompiler** (right): C-like pseudocode

#### Step 3: Finding main()

6. **Locate the main function**:
   - In Symbol Tree, expand: Functions → main
   - Double-click `main` to jump to it (if you compiled it on Mac, it might be `entry` instead)
   - You should see assembly in the Listing window
   - The Decompiler window shows C-like code

#### Step 4: Analyzing the Vulnerability

7. **Examine the decompiled code**:
   ```c
   // You should see something like:

    bool main(void)

    {
      bool bVar1;
      int iVar2;
      char acStack_18 [20];
      uint local_4;

      local_4 = 0;
      puts("=== Secure Login System v1.0 ===");
      printf("Enter the password: ");
      gets(acStack_18);
      printf("authorized: %d\n",(ulong)local_4);
      iVar2 = strcmp(acStack_18,"secret123");
      if (iVar2 == 0) {
        local_4 = 1;
        puts("Password correct!");
      }
      else {
        puts("Wrong password.");
      }
      bVar1 = local_4 == 0;
      if (bVar1) {
        puts("Access denied.");
      }
      else {
        puts("Access granted! Welcome to the secure system.");
        puts("Flag: RE_OVERFLOW_SUCCESS");
      }
      return bVar1;
    }
   ```

8. **Identify key information**:
   - `acStack_18`: The password buffer (16 bytes)
   - `local_4`: The authorized variable
   - `gets(acStack_18)`: The vulnerable function call
   - Note the variable ordering on the stack

#### Step 5: Additional Analysis Techniques

9. **String analysis**:
    - Window → Defined Strings
    - Look for interesting strings like passwords or flags

10. **Function graph view**:
    - In a function, click the graph icon (or press G)
    - Shows control flow visually
    - Useful for understanding complex logic

#### Step 6: Document Your Findings

11. **Add comments in Ghidra**:
    - Right-click any line → Comments → Set...
    - Document your understanding:
      ```
      ; Vulnerable gets() call - no bounds checking
      ; Buffer is 16 bytes, can overflow into authorized variable
      ```

12. **Rename variables for clarity**:
    - Right-click on `local_28` → Rename Variable
    - Change to `password_buffer`
    - Do the same for `local_18` → `is_authorized`

You can rename variables to deobfuscate the code. Press `L` to rename the variables and give them meaningful names like `password_buffer` and `authorized_flag`.

### Exercise 1.2: Basic Buffer Overflow

> **Difficulty**: 🔴🔴⚪⚪⚪
> **Importance**: 🔵🔵🔵🔵🔵
>
> You should spend up to ~20 minutes on this exercise.

Exploit the buffer overflow to bypass authentication without knowing the password.


```python


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
    pass
from w2d1_re_test import test_basic_overflow


test_basic_overflow(exploit_basic_overflow, compile_vulnerable_binary)
```

## Exercise 2: Finding Hidden Passwords

Sometimes the password is hidden in the binary itself. Let's learn how to extract it!

<details>
<summary>Vocabulary: Binary Analysis</summary><blockquote>

- **Strings**: Human-readable text embedded in a binary
- **Disassembly**: Converting machine code back to assembly instructions
- **Decompilation**: Converting assembly to higher-level pseudocode
- **Symbol**: A name associated with a memory address (like function names)

</blockquote></details>

There are several ways to find hardcoded passwords:

1. **Using `strings` command**: Extracts all printable strings from a binary
2. **Using Ghidra**: Decompile and analyze the code
3. **Using `objdump`**: Disassemble specific functions
4. **Dynamic analysis**: Run with a debugger and watch comparisons

### Exercise 2.1: Extract the Password

> **Difficulty**: 🔴⚪⚪⚪⚪
> **Importance**: 🔵🔵🔵⚪⚪
>
> You should spend up to ~10 minutes on this exercise.

Find the hardcoded password in the binary and use it to authenticate.


```python


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
    pass
from w2d1_re_test import test_password_extraction


test_password_extraction(find_password_in_binary)
```

## Exercise 3: Return Address Overwriting

Now let's move to a more advanced technique: overwriting the return address to redirect program execution.

<details>
<summary>Vocabulary: Advanced Exploitation</summary><blockquote>

- **Return address**: Where the CPU continues execution after a function returns
- **EIP/RIP**: Instruction pointer register (32-bit/64-bit) that points to the next instruction
- **NOP sled**: A sequence of no-operation instructions used as a landing pad
- **ASLR**: Address Space Layout Randomization - randomizes memory addresses
- **Stack canary**: A random value placed between buffers and return addresses to detect overflows

</blockquote></details>

In second.c, we have:
```c
void admin_access() { /* Prints flag */ }
void verify_user(char *password) {
    char buffer[32];
    strcpy(buffer, password);  // VULNERABLE!
    // ... password checking ...
}
```

The goal: Overflow buffer to overwrite the return address with the address of `admin_access()`

Stack layout:
```
[Higher addresses]
├─────────────────┤
│  Return address │ <- Overwrite this with admin_access()
├─────────────────┤
│  Saved EBP      │
├─────────────────┤
│  buffer[32]     │ <- Our input starts here
├─────────────────┤
[Lower addresses]
```



### Exercise 3.1: Craft Return Address Overwrite Exploit

> **Difficulty**: 🔴🔴🔴🔴🔴
> **Importance**: 🔵🔵🔵🔵🔵
>
> You should spend up to ~20 minutes on this exercise.

<details>
<summary>Hint: finding the address we want to jump to</summary><blockquote>

You can find the address of the `admin_access` function using Ghidra or `objdump`. Try `objdump -t second`
</blockquote></details>

<details>
<summary>Hint: crafting the payload</summary><blockquote>

You can use Python to create the payload, especially to print non-standard characters. For example, if you wanted to try "hello" as the password, you could do:
```shell
./second "$(python -c 'import sys; sys.stdout.buffer.write(b"hello")')"
```
</blockquote></details>

<details>
<summary>Solution</summary><blockquote>

```shell
./second "$(python -c "import sys; sys.stdout.buffer.write(b'A'*72 + b'\x66\x11\x40\x00\n')")"  # replace with your address
```
</blockquote></details>

### Exercise 3.2: Reverse Engineer the binary, find the password

> **Difficulty**: 🔴🔴⚪⚪⚪
> **Importance**: 🔵⚪⚪⚪⚪
>
> You should spend up to ~20 minutes on this exercise.

Look at the simple_hash function, and find an input x where `simple_hash(x) == 6385045028`, the target hash value.
Think about w1d4, where we looked at the properties of hash functions. Do you think this is a good hash function?

<details>
<summary>Hint</summary><blockquote>

The hash function is quite simple - you can try brute-forcing it with a script, or understand the code from the
decompilation.

The hash function is not good because
1. it does not use a large enough space of output values (unsigned long is only 8 bytes)
2. it does not provide enough diffusion, and you can simply figure out the inverse operations
</blockquote></details>

<details>
<summary>Solution</summary><blockquote>

The password is 'aisb'
</blockquote></details>


## Exercise 4: Shellcode Injection

The ultimate buffer overflow technique: injecting and executing your own code!

<details>
<summary>Vocabulary: Shellcode</summary><blockquote>

- **Shellcode**: Machine code that spawns a shell or performs other actions
- **Position-independent code**: Code that works regardless of where it's loaded in memory
- **NOP sled**: A sequence of NOP (0x90) instructions that "slide" execution to the shellcode
- **Null-free shellcode**: Shellcode without 0x00 bytes (which would terminate string functions)

</blockquote></details>

Basic shellcode injection strategy:
1. Fill buffer with NOP sled + shellcode
2. Overwrite return address to point somewhere in the NOP sled
3. CPU slides down NOPs until it hits shellcode

Layout:
```
[Buffer start] NOP NOP NOP NOP [Shellcode] NOP NOP [Return addr pointing to NOPs]
```

### Exercise 4.1: Create a Shellcode Payload

> **Difficulty**: 🔴🔴🔴🔴🔴
> **Importance**: 🔵🔵🔵🔵⚪
>
> You should spend up to ~25 minutes on this exercise.

Create a buffer overflow exploit that injects and executes shellcode.


```python


def create_shellcode_exploit(buffer_size: int = 128, shellcode: Optional[bytes] = None) -> bytes:
    """
    Create a shellcode injection exploit.

    Args:
        buffer_size: Total size of the vulnerable buffer
        shellcode: The shellcode to execute (default: execve("/bin/sh"))

    Returns:
        Complete exploit payload
    """
    # TODO: Create shellcode injection payload
    # 1. Create or use provided shellcode
    # 2. Prepend with NOP sled (0x90 bytes)
    # 3. Calculate return address to point into NOP sled
    # 4. Append return address in little-endian format
    pass
from w2d1_re_test import test_shellcode_basics


test_shellcode_basics(create_shellcode_exploit)
```

## Exercise 5: Modern Protections and Bypasses (optional)

Modern systems have multiple protections against buffer overflows. Let's understand them!

<details>
<summary>Vocabulary: Security Mitigations</summary><blockquote>

- **Stack Canaries**: Random values placed between buffers and return addresses
- **DEP/NX**: Data Execution Prevention - marks stack as non-executable
- **ASLR**: Address Space Layout Randomization - randomizes memory layout
- **PIE**: Position Independent Executable - randomizes code addresses
- **FORTIFY_SOURCE**: Compile-time buffer overflow detection

</blockquote></details>

### Understanding Protection Flags

When compiling our vulnerable programs, we disabled several protections:
- `-fno-stack-protector`: Disables stack canaries
- `-z execstack`: Allows executing code on the stack
- `-no-pie`: Disables position-independent code
- `-g`: Includes debug symbols

### Exercise 5.1: Identify Active Protections

> **Difficulty**: 🔴🔴⚪⚪⚪
> **Importance**: 🔵🔵🔵🔵⚪
>
> You should spend up to ~10 minutes on this exercise.

Learn to check what protections are enabled on a binary.


```python


def check_binary_protections(binary_path: str) -> dict:
    """
    Check which security protections are enabled on a binary.

    Args:
        binary_path: Path to the binary to check

    Returns:
        Dictionary of protection_name: enabled (bool)
    """
    # TODO: Implement protection checking
    # Use readelf, objdump, or checksec to identify protections
    pass
from w2d1_re_test import test_protection_checking

test_protection_checking(exec_sh)
```

## Exercise 6: Bypassing Protections (optional)

> **Difficulty**: 🔴🔴🔴🔴🔴
> **Importance**: 🔵🔵🔵🔵🔵
>
> You should spend up to ~90 minutes on this exercise.

Here's a [good challenge](https://github.com/HHousen/PicoCTF-2019/blob/master/Binary%20Exploitation/CanaRy/vuln.c) from picoCTF about bypassing canaries (it also has a [writeup](https://github.com/HHousen/PicoCTF-2019/blob/master/Binary%20Exploitation/CanaRy/README.md)).
