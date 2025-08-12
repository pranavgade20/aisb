# %%
import requests
import tarfile
import json
import sys
import os
import platform
from io import BytesIO
from typing import Optional, List, Union, Tuple, Dict, Any
import subprocess
import asyncio


def exec_sh(command: str, timeout: Optional[int | None] = 30, check_retcode=True) -> subprocess.CompletedProcess:
    """
    Execute shell commands with consistent parameters.

    Args:
        command: Shell command to execute (can be multiline)
        timeout: Optional timeout in seconds

    Returns:
        CompletedProcess object with result
    """
    return subprocess.run(command, shell=True, capture_output=True, text=True, check=check_retcode, timeout=timeout)


# Architecture detection
TARGET_ARCH, TARGET_VARIANT = {
    "x86_64": ("amd64", None),
    "amd64": ("amd64", None),
    "arm64": ("arm64", "v8"),
    "aarch64": ("arm64", "v8"),
    "armv7l": ("arm", "v7"),
    "armv6l": ("arm", "v6"),
}.get(platform.machine().lower(), ("amd64", None))

print(f"Detected architecture: {TARGET_ARCH} {TARGET_VARIANT if TARGET_VARIANT else ''}")

# Safety checks
if not os.path.exists("/.dockerenv"):
    print(
        "❌ ERROR: Not in Docker container or Docker container is not properly set up! Run inside the provided container."
    )
    sys.exit(1)
print("✅ Environment checks passed")


def parse_image_reference(image_ref: str) -> Tuple[str, str, str]:
    """
    Parse a Docker image reference into registry, image, and tag components.

    Args:
        image_ref: Image reference in various formats

    Returns:
        Tuple of (registry, image, tag)

    Examples:
        parse_image_reference("hello-world:latest") -> ("registry-1.docker.io", "library/hello-world", "latest")
        parse_image_reference("gcr.io/project/image:v1.0") -> ("gcr.io", "project/image", "v1.0")
    """
    # Implement image reference parsing
    # - Check if the image reference starts with 'http' to identify full URLs
    if image_ref.startswith("http"):
        # - For full URLs, remove protocol and split by '/' to extract components
        parsed_arr = image_ref.replace("https://", "").replace("http://", "").split("/")
        registry = parsed_arr[0]
        if "/manifests/" in image_ref:
            # Extract image and tag from URL
            image_parts = "/".join(parsed_arr[2:]).split("/manifests/")
            image = image_parts[0]
            tag = image_parts[1]
        else:
            image = "/".join(parsed_arr[1:-1])
            tag = parsed_arr[-1] if ":" in parsed_arr[-1] else "latest"
    else:
        if "/" in image_ref and "." in image_ref.split("/")[0]:
            # - For custom registries, look for dots in the first part (e.g., gcr.io)
            parsed_arr = image_ref.split("/", 1)
            registry = parsed_arr[0]
            image_and_tag = parsed_arr[1]
        else:
            # - For Docker Hub images, default to 'registry-1.docker.io' and add 'library/' prefix if needed
            # - Use rsplit(':', 1) to handle image names that might contain colons
            # Docker Hub
            registry = "mirror.gcr.io"
            image_and_tag = image_ref
            if "/" not in image_and_tag:
                image_and_tag = f"library/{image_and_tag}"

        if ":" in image_and_tag:
            image, tag = image_and_tag.split(":")
        else:
            # - Default to 'latest' tag if none is specified
            image = image_and_tag
            tag = "latest"

    return registry, image, tag


from w2d2_test import test_parse_image_reference

test_parse_image_reference(parse_image_reference)
# %%


def get_auth_token(registry: str, image: str) -> Dict[str, str]:
    """
    Get authentication headers for Docker registry access.

    Args:
        registry: Registry hostname (e.g., "registry-1.docker.io")
        image: Image name (e.g., "library/hello-world")

    Returns:
        Dictionary of headers to include in registry requests
    """
    # TODO: Authentication implementation
    # 1. Initialize empty headers dictionary
    headers = {"Authorization": ""}
    # 2. Check if registry is Docker Hub (registry-1.docker.io)
    # if registry == "mirror.gcr.io":
    if registry == "registry-1.docker.io":
        # 3. For Docker Hub, construct token URL with service and scope parameters
        url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{image}:pull"
        # 4. Make HTTP request to auth.docker.io/token
        response = requests.get(url)
        response.raise_for_status()
        # 5. Parse JSON response to extract token
        token = response.json()["token"]
        # 6. Add Authorization header with Bearer token
        headers["Authorization"] = f"Bearer {token}"
    # 7. Return headers dictionary

    return headers


from w2d2_test import test_get_auth_token

test_get_auth_token(get_auth_token)

# %%


def get_target_manifest(
    registry: str, image: str, tag: str, headers: Dict[str, str], target_arch: str, target_variant: Optional[str] = None
) -> str:
    """
    Get the manifest digest for the target architecture.

    Args:
        registry: Registry hostname
        image: Image name
        tag: Image tag
        headers: Authentication headers
        target_arch: Target architecture (e.g., "amd64", "arm64")
        target_variant: Optional architecture variant (e.g., "v8")

    Returns:
        Manifest digest for the target architecture

    Raises:
        ValueError: If target architecture is not found
    """
    # Implement manifest discovery
    # 1. Build manifest list URL
    url = f"https://{registry}/v2/{image}/manifests/{tag}"
    # 2. Make HTTP request with headers
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    # 3. Parse JSON response
    manifest_list = response.json()["manifests"]
    # 4. Find manifest matching target_arch and target_variant
    for manifest in manifest_list:
        platform = manifest["platform"]
        proposed_architecture = platform["architecture"]
        if "variant" in list(platform.keys()):
            proposed_variant = platform["variant"]
        else:
            proposed_variant = None
        if proposed_architecture == target_arch and target_variant == proposed_variant:
            return manifest["digest"]
    # 5. Return the digest, or raise ValueError if not found
    raise ValueError("Architecture and variant did not match anything in manifest list.")


from w2d2_test import test_get_target_manifest

test_get_target_manifest(get_target_manifest, get_auth_token)


# %%
def get_manifest_layers(
    registry: str, image: str, manifest_digest: str, headers: Dict[str, str]
) -> List[Dict[str, Any]]:
    """
    Get the layer information from a manifest.

    Args:
        registry: Registry hostname
        image: Image name
        manifest_digest: Manifest digest
        headers: Authentication headers

    Returns:
        List of layer dictionaries with 'digest' and 'size' keys
    """
    # TODO: Implement manifest processing
    # 1. Build manifest URL using digest
    url = f"https://{registry}/v2/{image}/manifests/{manifest_digest}"
    # 2. Add Accept header for v2 manifest format
    headers_copy = headers.copy()
    headers_copy["Accept"] = (
        "application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json"
    )
    # 3. Make HTTP request
    try:
        response = requests.get(url, headers=headers_copy)
        response.raise_for_status()
        # 4. Parse JSON and extract layers
        responsejson = response.json()
        # 5. Return list of layer dictionaries
        layers = responsejson.get("layers", [])
        return layers  # Placeholder return
    except Exception:
        return []


from w2d2_test import test_get_manifest_layers

test_get_manifest_layers(get_manifest_layers, get_auth_token, get_target_manifest)

# %%


import subprocess


def run_chroot(
    chroot_dir: str, command: Optional[Union[str, List[str]]] = None
) -> Optional[subprocess.CompletedProcess]:
    """
    Run a command in a chrooted environment.

    This function creates an isolated filesystem environment by changing the root directory
    for the executed command. The process will only be able to access files within the
    specified chroot directory.

    Args:
        chroot_dir: Directory to chroot into (must contain necessary binaries and libraries)
        command: Command to run (default: /bin/sh)
                - If string: executed as shell command
                - If list: executed directly
                - If None: defaults to interactive shell

    Returns:
        CompletedProcess object with execution results, or None if error/timeout
    """
    # Implement chroot command execution
    # 1. Handle different command formats (None, string, list)
    shell_command = ["chroot", chroot_dir]
    if type(command) == str:
        # 2. Build the chroot command: ['chroot', chroot_dir] + command
        shell_command.append(command)
    elif type(command) == List:  # noqa: E721
        for cmd in command:
            shell_command.append(cmd)
    else:
        # type None
        pass
    try:
        # 3. Execute with subprocess.run() with timeout and output capture
        result = subprocess.run(shell_command, capture_output=True, timeout=15)
        # 4. Print execution details and results
        subprocess.run(["echo", result])
    # 5. Handle TimeoutExpired and other exceptions
    except TimeoutError:
        subprocess.run(["echo", "Timed out!"])
        result = None
    except Exception:
        subprocess.run(["echo", f"ERROR! {Exception}"])
        result = None

    # 6. Return the result or None on error
    return result


from w2d2_test import test_run_chroot

# Run the test
test_run_chroot(run_chroot)

# %%
import signal
import time


def create_cgroup(cgroup_name, memory_limit=None, cpu_limit=None):
    """
    Create a cgroup with specified limits

    Args:
        cgroup_name: Name of the cgroup (e.g., 'demo')
        memory_limit: Memory limit (e.g., '100M', '1000000')
        cpu_limit: CPU limit (stretch)

    Returns:
        Path to the created cgroup
    """
    # Implement basic cgroup creation
    # 1. Create a new cgroup directory with path /sys/fs/cgroup/{cgroup_name} - you will write files in this directory to configure the cgroup
    try:
        if os.path.isdir(f"/sys/fs/cgroup/{cgroup_name}"):
            pass
        else:
            subprocess.run(["sudo", "mkdir", f"/sys/fs/cgroup/{cgroup_name}"])
        # 2. Enable controllers (+cpu +memory +pids) in parent cgroup
        subprocess.run(
            ["echo", "+cpu", "+memory", "+pids", ">>", f"/sys/fs/cgroup/{cgroup_name}/cgroup.subtree_control"]
        )
        # 3. Set memory limit if specified - write the memory limit to {cgroup_path}/memory.max, which will tell the kernel how much memory the cgroup can use
        if memory_limit:
            subprocess.run(["echo", memory_limit, ">>", f"/sys/fs/cgroup/{cgroup_name}/memory.max"])
        # 4. Return the cgroup path
        return f"/sys/fs/cgroup/{cgroup_name}"
    # 5. Handle errors and return None on failure
    except Exception:
        return None


from w2d2_test import test_create_cgroup

# test_create_cgroup(create_cgroup)

# %%


def add_process_to_cgroup(cgroup_name, pid=None):
    """
    Add a process to a cgroup

    Args:
        cgroup_name: Name of the cgroup
        pid: Process ID (default: current process)
    """
    try:
        # Implement process assignment to cgroup
        # 1. Use current process PID if none specified
        if pid is None:
            pid = os.getpid()
        # 2. Write PID to cgroup.procs file
        subprocess.run(["echo", f"{pid}", ">>", f"/sys/fs/cgroup/{cgroup_name}/cgroup.procs"])
        # 3. Handle errors and return success status
        return True
    except Exception:
        subprocess.run(["echo", "ERROR in setting pids"])
        return False


from w2d2_test import test_add_process_to_cgroup

test_add_process_to_cgroup(add_process_to_cgroup, create_cgroup)

# %%


def run_in_cgroup_chroot(cgroup_name, chroot_dir, command=None, memory_limit="100M"):
    """
    Run a command in both a cgroup and chroot environment

    Args:
        cgroup_name: Name of the cgroup to create/use
        chroot_dir: Directory to chroot into
        command: Command to run
        memory_limit: Memory limit for the cgroup
    """
    # Create cgroup
    create_cgroup(cgroup_name, memory_limit=memory_limit)

    if command is None:
        command = ["/bin/sh"]
    elif isinstance(command, str):
        command = ["/bin/sh", "-c", command]

    # Create a shell script that adds the process to cgroup then chroots
    script = f"""
    echo $$ > /sys/fs/cgroup/{cgroup_name}/cgroup.procs
    chroot {chroot_dir} {" ".join(command)}
    """

    # Run without capturing output so we see it in real-time
    result = subprocess.run(["sh", "-c", script], timeout=60)
    return result


from w2d2_test import test_memory_simple
from w2d2_test import test_run_in_cgroup_chroot

test_run_in_cgroup_chroot(run_in_cgroup_chroot, create_cgroup)

# %%


def create_cgroup_comprehensive_part1(cgroup_name, memory, cpu):
    """
    Create a cgroup with comprehensive settings - Part 1: Basic setup

    Args:
        cgroup_name: Name of the cgroup (e.g., 'demo')
        memory_limit: Memory limit (e.g., '100M', '1000000')
        cpu_limit: CPU limit (not implemented yet)
    """
    try:
        # Implement basic cgroup creation with swap disabling
        # 1. Call create_cgroup() with the correct parameters to create the cgroup
        cgroup_path = create_cgroup(cgroup_name, memory)
        # 2. Disable swap - search for "swap.max" in https://docs.kernel.org/admin-guide/cgroup-v2.html
        subprocess.run(["echo", 0, ">>", f"/sys/fs/cgroup/{cgroup_name}/memory.swap.max"])
        # 3. Return cgroup path or None if critical steps fail
        return cgroup_path
    except Exception:
        return None


from w2d2_test import test_create_cgroup_comprehensive_part1

test_create_cgroup_comprehensive_part1(create_cgroup_comprehensive_part1)

# %%


def run_in_cgroup_chroot_namespaced(cgroup_name, chroot_dir, command=None, memory_limit="100M"):
    """
    Run a command in cgroup, chroot, and namespace isolation

    Args:
        cgroup_name: Name of the cgroup to create/use
        chroot_dir: Directory to chroot into (must contain basic filesystem structure)
        command: Command to run (defaults to /bin/sh if None)
        memory_limit: Memory limit for the cgroup (e.g., "100M")

    Returns:
        Exit code of the command, or None if error occurred
    """
    # Create cgroup with memory limit
    create_cgroup(cgroup_name, memory_limit=memory_limit)

    # Prepare command - default to shell if none provided
    if command is None:
        command = ["/bin/sh"]
    elif isinstance(command, str):
        command = ["/bin/sh", "-c", command]

    print(f"Running `{command}` in cgroup {cgroup_name} with chroot {chroot_dir} and namespaces")
    # TODO: Implement namespace isolation following these steps:

    # Step 1: Fork a child process
    # (Creates a copy of our program - parent and child run separately)
    # Learn more: https://linuxhint.com/fork-system-call-linux/ and https://www.w3schools.com/python/ref_os_fork.asp
    # documentation: https://docs.python.org/3/library/os.html#os.fork
    p = os.fork()
    if p == 0:
        print("We are in the child process.")

        # Step 2: In child process:
        #   - Set up signal handler for SIGUSR1 (like a doorbell to wake up the child)

        signal.signal(signal.SIGUSR1, handler=signal.SIG_DFL)
        #     See: https://docs.python.org/3/library/signal.html
        #   - Wait for parent to finish setup and send a signal
        signal.pause()

    else:
        pass
    #   - After receiving signal, use unshare command to create isolated environments:
    #     See: https://man7.org/linux/man-pages/man1/unshare.1.html

    # Step 3: In parent process:
    #   - Add child PID to cgroup (to limit resources like memory/CPU)
    #   - Send SIGUSR1 signal to child (tells it "you're ready to start")
    #   - Wait for child to finish running
    #   - Get the exit code to report success/failure

    # Think about why we did .fork() and the complicated signalling, as opposed to just running the commands sequentially.
    pass


# %%

import uuid


def create_bridge_interface():
    """
    Create and configure bridge0 interface with IP address
    """
    # Check if bridge already exists
    bridge_check = exec_sh("ip link show bridge0", check_retcode=False)
    if bridge_check.returncode == 0:
        print("✓ Bridge0 already exists, checking configuration...")
        # Check if it has the right IP
        ip_check = exec_sh("ip addr show bridge0")
        if "10.0.0.1/24" in ip_check.stdout:
            print("✓ Bridge0 already configured with correct IP")
            return True
        else:
            print("⚠ Bridge0 exists but needs reconfiguration")

    # Remove existing bridge if it exists
    exec_sh("ip link del bridge0", check_retcode=False)

    # Create and configure bridge
    exec_sh("""
        ip link add bridge0 type bridge
        ip addr add 10.0.0.1/24 dev bridge0
        ip link set bridge0 up
    """)

    print("✓ Created bridge0")
    print("✓ Added IP 10.0.0.1/24 to bridge0")
    print("✓ Bridge0 is up")

    return True


from w2d2_test import test_bridge_interface

# Run the test
test_bridge_interface(create_bridge_interface, exec_sh)

# %%

import threading

# Dangerous syscalls for CVE-2024-0137
DANGEROUS_SYSCALLS = {"setns", "unshare", "mount", "pivot_root", "chroot", "clone", "socket", "bind", "connect"}


def monitor_container_syscalls(container_command, alert_callback):
    """
    Monitor syscalls by running strace INSIDE the container namespace

    Args:
        container_command: List of command and arguments to run in container
        alert_callback: Function to call when dangerous syscalls are detected

    Returns:
        Exit code of the monitored process
    """

    # Build strace command that runs inside the container
    strace_cmd = [
        "strace",
        "-f",
        "-e",
        "trace=" + ",".join(DANGEROUS_SYSCALLS),
        "-o",
        "/dev/stderr",  # Send to stderr for monitoring
    ] + container_command

    print(f"🔍 Running strace inside container: {' '.join(strace_cmd)}")

    # Check if container_command matches our legitimate container setup pattern
    legitimate_pattern = ["unshare", "--pid", "--mount", "--net", "--uts", "--ipc", "--fork", "chroot"]
    is_legitimate_setup = False
    if len(container_command) >= len(legitimate_pattern):
        # Check if the container command starts with our legitimate pattern
        if all(container_command[i] == legitimate_pattern[i] for i in range(len(legitimate_pattern))):
            is_legitimate_setup = True
            print("✓ Identified legitimate container setup sequence - initial unshare will be allowed")

    process = subprocess.Popen(strace_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

    # Monitor stderr for syscall traces
    def monitor_stderr():
        if process.stderr:
            # Track if we've seen the initial legitimate unshare
            initial_unshare_seen = False

            for line in iter(process.stderr.readline, ""):
                if line.strip():
                    # Check for dangerous syscalls
                    if any(syscall in line for syscall in DANGEROUS_SYSCALLS):
                        # If this is a legitimate setup and it's the initial unshare syscall
                        if (
                            is_legitimate_setup
                            and "unshare" in line
                            and ("CLONE_NEWNET" in line or "--net" in line)
                            and not initial_unshare_seen
                        ):
                            # Skip the alert for this initial legitimate unshare
                            initial_unshare_seen = True
                            print(f"✓ Allowed initial container setup: {line.strip()}")
                        else:
                            # This is a suspicious syscall, trigger the alert
                            alert_callback(line.strip(), process.pid)
                    # Also print container output
                    if not any(syscall in line for syscall in DANGEROUS_SYSCALLS):
                        print(f"[CONTAINER] {line.strip()}")

    # Monitor stdout for normal output
    def monitor_stdout():
        if process.stdout:
            for line in iter(process.stdout.readline, ""):
                if line.strip():
                    print(f"[CONTAINER] {line.strip()}")

    # Start monitoring threads
    stderr_thread = threading.Thread(target=monitor_stderr, daemon=True)
    stdout_thread = threading.Thread(target=monitor_stdout, daemon=True)

    stderr_thread.start()
    stdout_thread.start()

    # Wait for process completion
    exit_code = process.wait()
    return exit_code


from w2d2_test import test_syscall_monitoring

# Run the test
test_syscall_monitoring()


def security_alert_handler(syscall_line, pid):
    """
    Enhanced alert handler for CVE-2024-0137 and other container escape attempts

    Args:
        syscall_line: The strace output line containing the syscall
        pid: Process ID that made the syscall
    """

    print("🚨 SECURITY ALERT: Dangerous syscall detected!")
    print(f"   Syscall trace: {syscall_line}")
    print(f"   Process PID: {pid}")

    # Specific CVE-2024-0137 detection patterns
    if "unshare" in syscall_line and ("CLONE_NEWNET" in syscall_line):
        print("🔥 CRITICAL: CVE-2024-0137 network namespace escape detected!")
        print("   Terminating malicious container...")
        # TODO: Kill the entire process group

        pass  # Exit the Python process on critical failure

    elif "setns" in syscall_line:
        print("🔥 CRITICAL: Namespace manipulation detected!")
        print("   Possible container escape attempt!")
        # Log but don't kill immediately - might be legitimate

    elif "mount" in syscall_line:
        print("⚠ WARNING: Filesystem mount detected!")
        print("   Monitor for privilege escalation attempts")

    elif "pivot_root" in syscall_line:
        print("🔥 CRITICAL: Root filesystem manipulation detected!")
        print("   Possible container breakout attempt!")

    else:
        print("⚠ WARNING: Suspicious syscall detected")
        print("   Review for potential security implications")


from w2d2_test import test_security_alerts


# Run the test
test_security_alerts()
