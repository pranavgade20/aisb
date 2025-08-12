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


# %%


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
    # Parse image reference
    if image_ref.startswith("http"):
        # Full URL provided
        parts = image_ref.replace("https://", "").replace("http://", "").split("/")
        registry = parts[0]
        if "/manifests/" in image_ref:
            # Extract image and tag from URL
            image_parts = "/".join(parts[2:]).split("/manifests/")
            image = image_parts[0]
            tag = image_parts[1]
        else:
            image = "/".join(parts[1:-1])
            tag = parts[-1] if ":" in parts[-1] else "latest"
    else:
        # Docker image format (e.g., "hello-world:latest" or "gcr.io/project/image:tag")
        if "/" in image_ref and image_ref.split("/")[0].count(".") > 0:
            # Custom registry (e.g., gcr.io/project/image)
            parts = image_ref.split("/", 1)
            registry = parts[0]
            image_and_tag = parts[1]
        else:
            # Docker Hub
            registry = "mirror.gcr.io"  # Default to Docker Hub mirror
            image_and_tag = image_ref
            if "/" not in image_and_tag:
                image_and_tag = f"library/{image_and_tag}"

        if ":" in image_and_tag:
            image, tag = image_and_tag.rsplit(":", 1)
        else:
            image = image_and_tag
            tag = "latest"

    return registry, image, tag

    # TODO: Implement image reference parsing
    # - Check if the image reference starts with 'http' to identify full URLs
    # - For full URLs, remove protocol and split by '/' to extract components
    # - For custom registries, look for dots in the first part (e.g., gcr.io)
    # - For Docker Hub images, default to 'registry-1.docker.io' and add 'library/' prefix if needed
    # - Use rsplit(':', 1) to handle image names that might contain colons
    # - Default to 'latest' tag if none is specified
    return "registry-1.docker.io", "library/hello-world", "latest"  # Placeholder return


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

    headers = {}
    if registry == "registry-1.docker.io":
        token_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{image}:pull"
        token = requests.get(token_url).json()["token"]
        # token_resp.raise_for_status()
        # token = token_resp
        headers["Authorization"] = f"Bearer {token}"

    return headers
    # TODO: Authentication implementation
    # 1. Initialize empty headers dictionary
    # 2. Check if registry is Docker Hub (registry-1.docker.io)
    # 3. For Docker Hub, construct token URL with service and scope parameters
    # 4. Make HTTP request to auth.docker.io/token
    # 5. Parse JSON response to extract token
    # 6. Add Authorization header with Bearer token
    # 7. Return headers dictionary
    return {}  # Placeholder return


from w2d2_test import test_get_auth_token

test_get_auth_token(get_auth_token)

# %%


from typing import Optional


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

    manifest_url = f"https://{registry}/v2/{image}/manifests/{tag}"
    list = requests.get(manifest_url).json()["manifests"]

    for manifest in list:
        if manifest["platform"]["architecture"] == target_arch:
            if target_variant:
                if manifest["platform"]["variant"] == target_variant:
                    return manifest["digest"]
                else:
                    continue
            else:
                return manifest["digest"]
    raise ValueError("Target doesn't exist")
    # TODO: Implement manifest discovery
    # 1. Build manifest list URL
    # 2. Make HTTP request with headers
    # 3. Parse JSON response
    # 4. Find manifest matching target_arch and target_variant
    # 5. Return the digest, or raise ValueError if not found
    return "sha256:placeholder"  # Placeholder return


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
    url = f"https://{registry}/v2/{image}/manifests/{manifest_digest}"
    manifest_doc = requests.get(url, headers=headers).json()

    layers = manifest_doc["layers"]
    return layers

    # TODO: Implement manifest processing
    # 1. Build manifest URL using digest
    # 2. Add Accept header for v2 manifest format
    # 3. Make HTTP request
    # 4. Parse JSON and extract layers
    # 5. Return list of layer dictionaries
    return []  # Placeholder return


from w2d2_test import test_get_manifest_layers

test_get_manifest_layers(get_manifest_layers, get_auth_token, get_target_manifest)


# %%

import w2d2_test


# Make the constants visible to the test helper
w2d2_test.TARGET_ARCH = TARGET_ARCH
w2d2_test.TARGET_VARIANT = TARGET_VARIANT


def download_and_extract_layers(
    registry: str, image: str, layers: List[Dict[str, Any]], headers: Dict[str, str], output_dir: str
) -> None:
    """
    Download and extract all layers to the output directory.


    Args:
        registry: Registry hostname
        image: Image name
        layers: List of layer dictionaries from manifest
        headers: Authentication headers
        output_dir: Directory to extract layers to
    """
    # TODO: Implement layer download and extraction

    os.mkdir(output_dir)

    for layer in layers:
        digest = layer["digest"]
        blob_url = f"https://{registry}/v2/{image}/blobs/{digest}"

        blob = requests.get(blob_url, headers=headers, stream=True)
        blob.raise_for_status()

        with tarfile.open(fileobj=BytesIO(blob.content), mode="r:gz") as tar:
            tar.extractall(output_dir)

    print(f"\n✓ Extracted {len(layers)} layers to {output_dir}")

    # 1. Create output directory
    # 2. For each layer:
    #    a. Build blob URL using digest
    #    b. Download blob with streaming
    #    c. Extract as gzipped tar to output_dir
    # 3. Print progress information
    pass


from w2d2_test import test_download_and_extract_layers

test_download_and_extract_layers(download_and_extract_layers, get_auth_token, get_target_manifest, get_manifest_layers)


# %%


def pull_layers(
    image_ref: str, output_dir: str, target_arch: str = TARGET_ARCH, target_variant: Optional[str] = TARGET_VARIANT
) -> None:
    """
    Pull and extract Docker image layers for a specific architecture.

    Args:
        image_ref: Docker image reference (various formats supported)
        output_dir: Directory to extract layers to
        target_arch: Target architecture (default: auto-detected)
        target_variant: Target architecture variant (default: auto-detected)
    """
    # TODO: Implement complete pull_layers function
    # Use all the functions you've implemented above:
    # 1. parse_image_reference()
    # 2. get_auth_token()
    # 3. get_target_manifest()
    # 4. get_manifest_layers()
    # 5. download_and_extract_layers()

    registry, image, tag = parse_image_reference(image_ref)

    headers = get_auth_token(registry, image)

    manifest_digest = get_target_manifest(registry, image, tag, headers, target_arch, target_variant)

    layers = get_manifest_layers(registry, image, manifest_digest, headers)

    download_and_extract_layers(registry, image, layers, headers, output_dir)

    pass


from w2d2_test import test_pull_layers_complete

test_pull_layers_complete(pull_layers)

# %%
pull_layers("alpine:latest", "./extracted_alpine")
pull_layers("python:3.12-alpine", "./extracted_python")


# %%


import os
import subprocess
from typing import List, Optional


def _find_chroot_dir(path: str) -> str | None:
    """
    Return a real path for `path`.

    If it doesn’t exist in the cwd, also try ../ and ../../ so we work no
    matter whether the notebook was launched from the repo root or from
    w2d2/.
    """
    cand = os.path.abspath(path)
    if os.path.isdir(cand):
        return cand

    # look one- and two-levels up
    for up in (1, 2):
        cand = os.path.abspath(os.path.join(os.getcwd(), *([".."] * up), path))
        if os.path.isdir(cand):
            return cand
    return None


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
    if command is None:
        command = ["/bin/sh"]
    elif isinstance(command, str):
        command = ["/bin/sh", "-c", command]

    print(f"Running chroot {chroot_dir} with command: {' '.join(command)}")

    result = subprocess.run(["chroot", chroot_dir] + command, capture_output=True, text=True, timeout=30)
    print(f"Exit code: {result.returncode}")
    if result.stdout:
        print(f"stdout:\n{result.stdout}")
    if result.stderr:
        print(f"stderr:\n{result.stderr}")
    return result


from w2d2_test import test_run_chroot

# Run the test
test_run_chroot(run_chroot)


# %%

import os
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
    cgroup_path = f"/sys/fs/cgroup/{cgroup_name}"
    os.makedirs(cgroup_path, exist_ok=True)
    with open("/sys/fs/cgroup/cgroup.subtree_control", "w") as f:
        f.write("+cpu +memory +pids")

    if memory_limit:
        memory_path = f"{cgroup_path}/memory.max"
        with open(memory_path, "w") as f:
            f.write(str(memory_limit))

    return cgroup_path
    # TODO: Implement basic cgroup creation
    # 1. Create a new cgroup directory with path /sys/fs/cgroup/{cgroup_name} - you will write files in this directory to configure the cgroup
    # 2. Enable controllers (+cpu +memory +pids) in parent cgroup
    # 3. Set memory limit if specified - write the memory limit to {cgroup_path}/memory.max, which will tell the kernel how much memory the cgroup can use
    # 4. Return the cgroup path
    # 5. Handle errors and return None on failure
    pass


from w2d2_test import test_create_cgroup

test_create_cgroup(create_cgroup)


# %%


def add_process_to_cgroup(cgroup_name, pid=None):
    """
    Add a process to a cgroup

    Args:
        cgroup_name: Name of the cgroup
        pid: Process ID (default: current process)
    """
    if pid is None:
        pid = os.getpid()

    cgroup_procs_path = f"/sys/fs/cgroup/{cgroup_name}/cgroup.procs"

    with open(cgroup_procs_path, "w") as f:
        f.write(str(pid))

    return True
    # TODO: Implement process assignment to cgroup
    # 1. Use current process PID if none specified
    # 2. Write PID to cgroup.procs file
    # 3. Handle errors and return success status
    pass


from w2d2_test import test_add_process_to_cgroup

test_add_process_to_cgroup(add_process_to_cgroup, create_cgroup)


# %%


import w2d2_test

# make your implementations available to the tests
w2d2_test.create_cgroup = create_cgroup
w2d2_test.add_process_to_cgroup = add_process_to_cgroup


import os
import subprocess
from typing import Optional, Union, List


import os
import subprocess
from typing import Optional, Union, List


def run_in_cgroup_chroot(
    cgroup_name: str,
    chroot_dir: str,
    command: Optional[Union[str, List[str]]] = None,
    memory_limit: str = "100M",
    timeout: int = 60,
) -> subprocess.CompletedProcess:
    """
    Run a command in both a cgroup and chroot environment.

    Args:
        cgroup_name: Name of the cgroup to create/use
        chroot_dir: Directory to chroot into
        command: Command to run (string or list). Defaults to ['/bin/sh']
        memory_limit: Memory limit for the cgroup (e.g., "100M")
        timeout: Seconds before killing the command

    Returns:
        subprocess.CompletedProcess with returncode, stdout, stderr
    """
    # 1. Create (or re-create) the cgroup with a memory limit
    cg_path = create_cgroup(cgroup_name, memory_limit=memory_limit)
    if cg_path is None:
        raise RuntimeError(f"Failed to create cgroup '{cgroup_name}'")

    # 2. Normalize the command into a list
    if command is None:
        cmd_list = ["/bin/sh"]
    elif isinstance(command, str):
        cmd_list = ["/bin/sh", "-c", command]
    else:
        cmd_list = command

    # 3. Build a shell snippet that:
    #    - writes its own PID into cgroup.procs
    #    - execs into the chroot with our command
    # Note: using exec so that the shell PID == the chrooted process
    cg_procs = os.path.join("/sys/fs/cgroup", cgroup_name, "cgroup.procs")
    inner_cmd = " ".join(subprocess.list2cmdline([arg]) for arg in cmd_list)
    shell_script = f"""
        set -e
        echo $$ > {cg_procs}
        exec chroot {subprocess.list2cmdline([chroot_dir])} {inner_cmd}
    """

    # 4. Run it
    result = subprocess.run(
        ["sh", "-c", shell_script],
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    return result


# make it visible to the test harness
import w2d2_test

w2d2_test.run_in_cgroup_chroot = run_in_cgroup_chroot

# finally, re-run the test
from w2d2_test import test_run_in_cgroup_chroot

test_run_in_cgroup_chroot(run_in_cgroup_chroot)


# %%


def create_cgroup_comprehensive_part1(cgroup_name, memory, cpu):
    """
    Create a cgroup with comprehensive settings - Part 1: Basic setup

    Args:
        cgroup_name: Name of the cgroup (e.g., 'demo')
        memory_limit: Memory limit (e.g., '100M', '1000000')
        cpu_limit: CPU limit (not implemented yet)
    """
    # TODO: Implement basic cgroup creation with swap disabling
    # 1. Call create_cgroup() with the correct parameters to create the cgroup
    # 2. Disable swap - search for "swap.max" in https://docs.kernel.org/admin-guide/cgroup-v2.html
    # 3. Return cgroup path or None if critical steps fail
    cg_path = create_cgroup(cgroup_name, memory_limit=memory, cpu_limit=cpu)
    if cg_path is None:
        raise RuntimeError(f"Failed to create cgroup '{cgroup_name}'")

    try:
        swap_max_path = f"{cg_path}/memory.swap.max"
        with open(swap_max_path, "w") as f:
            f.write("0")

    except Exception as e:
        print(e)
        return None

    return cg_path

    pass


from w2d2_test import test_create_cgroup_comprehensive_part1

test_create_cgroup_comprehensive_part1(create_cgroup_comprehensive_part1)


# %%


def create_cgroup_comprehensive(cgroup_name, memory_limit=None, cpu_limit=None):
    """
    Create a cgroup with comprehensive settings - Part 2: Advanced OOM and Process Management

    This builds on Part 1 by adding advanced Out-of-Memory handling, process assignment,
    and comprehensive monitoring capabilities for production-ready container isolation.

    Args:
        cgroup_name: Name of the cgroup (e.g., 'demo')
        memory_limit: Memory limit (e.g., '100M', '1000000')
        cpu_limit: CPU limit (not implemented yet)
    """
    # TODO: Part 2 implementation
    # 1. Call create_cgroup_comprehensive_part1()
    # 2. Enable OOM group killing + assign process + set OOM score (see the documentation!)
    # 3. Return cgroup path
    pass


from w2d2_test import test_memory_comprehensive
from w2d2_test import test_create_cgroup_comprehensive

test_create_cgroup_comprehensive(test_memory_comprehensive)


# %%

import w2d2_test

w2d2_test.exec_sh = exec_sh


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

    pid = os.fork()

    if pid == 0:

        def resume_handler(signum, frame):
            pass  # Just wake up from pause - no action needed

        signal.signal(signal.SIGUSR1, resume_handler)
        print(f"Child process {os.getpid()} waiting for signal...")

        # Step 3: Wait for parent to add us to cgroup
        signal.pause()  # Blocks until SIGUSR1 received
        print(f"Child process {os.getpid()} resuming...")

        # Step 4: Execute with namespace isolation using unshare
        # unshare creates new namespaces, then chroot isolates filesystem
        # Execute command with namespace isolation
        try:
            subprocess.run(
                [
                    "unshare",
                    "--pid",  # Process ID namespace isolation
                    "--mount",  # Mount namespace isolation
                    "--net",  # Network namespace isolation
                    "--uts",  # Hostname namespace isolation
                    "--ipc",  # IPC namespace isolation
                    "--fork",  # Fork after creating namespaces
                    "chroot",
                    chroot_dir,  # Change root directory
                ]
                + command,
                check=True,
            )
            # Child process must exit explicitly to avoid continuing parent code
            os._exit(0)
        except Exception as e:
            print(f"Child process error: {e}")
            os._exit(1)

    else:
        # PARENT PROCESS EXECUTION PATH

        print(f"Started paused process {pid}, adding to cgroup {cgroup_name}")

        # Step 5: Add child process to cgroup for resource limits
        if add_process_to_cgroup(cgroup_name, pid):
            print(f"Added process {pid} to cgroup {cgroup_name}")
        else:
            print(f"⚠ Warning: Could not add process {pid} to cgroup {cgroup_name}")

        # Step 6: Signal child to continue execution
        os.kill(pid, signal.SIGUSR1)
        print(f"Signaled process {pid} to continue")

        # Step 7: Wait for child process to complete
        _, status = os.waitpid(pid, 0)
        exit_code = os.WEXITSTATUS(status)

        print(f"Exit code: {exit_code}")
        return exit_code

    # Step 1: Fork a child process
    # (Creates a copy of our program - parent and child run separately)
    # Learn more: https://linuxhint.com/fork-system-call-linux/ and https://www.w3schools.com/python/ref_os_fork.asp
    # documentation: https://docs.python.org/3/library/os.html#os.fork

    # Step 2: In child process:
    #   - Set up signal handler for SIGUSR1 (like a doorbell to wake up the child)
    #     See: https://docs.python.org/3/library/signal.html
    #   - Wait for parent to finish setup and send a signal
    #   - After receiving signal, use unshare command to create isolated environments:
    #     See: https://man7.org/linux/man-pages/man1/unshare.1.html

    # Step 3: In parent process:
    #   - Add child PID to cgroup (to limit resources like memory/CPU)
    #   - Send SIGUSR1 signal to child (tells it "you're ready to start")
    #   - Wait for child to finish running
    #   - Get the exit code to report success/failure

    # Think about why we did .fork() and the complicated signalling, as opposed to just running the commands sequentially.
    pass


w2d2_test.run_in_cgroup_chroot_namespaced = run_in_cgroup_chroot_namespaced


from w2d2_test import test_namespace_isolation

test_namespace_isolation()


# %%


import uuid


def create_bridge_interface():
    """
    Create and configure bridge0 interface with IP address
    """
    # Check if running as root
    if os.geteuid() != 0:
        print("⚠ Warning: Bridge interface creation requires root privileges")
        print("Critical failure - bridge interface creation requires root privileges")
        sys.exit(1)  # Exit the Python process on critical failure

    brige_check = exec_sh("ip link show bridge0", check_retcode=False)
    if brige_check.returncode == 0:
        print("✓ Bridge0 already exists, checking configuration...")

        ip_check = exec_sh("ip addr show bridge0")

        if "10.0.0.1/24" in ip_check.stdout:
            return True
        else:
            pass

    exec_sh("ip link del bridge0", check_retcode=False)

    exec_sh("""
            ip link add bridge0 type bridge
            ip addr add 10.0.0.1/24 dev bridge0
            ip link set bridge0 up
        """)

    print("✓ Created bridge0")
    print("✓ Added IP 10.0.0.1/24 to bridge0")
    print("✓ Bridge0 is up")

    return True

    # TODO: Implement bridge interface creation
    #   - see docs: https://linux.die.net/man/8/ip
    #   - Check if bridge0 already exists
    #   - Remove existing bridge if present
    #   - Create bridge0 interface
    #   - Configure bridge0 with IP 10.0.0.1/24
    #   - Bring bridge0 up
    pass


from w2d2_test import test_bridge_interface

w2d2_test.create_bridge_interface = create_bridge_interface


# Run the test
test_bridge_interface()


# %%


def setup_nat_forwarding():
    """
    Set up NAT and forwarding rules for container internet access
    """
    # Check if running as root
    if os.geteuid() != 0:
        print("⚠ Warning: NAT setup requires root privileges")
        print("Critical failure - NAT setup requires root privileges")
        sys.exit(1)  # Exit the Python process on critical failure

    # TODO: Implement NAT and forwarding setup
    #   - Enable IP forwarding with sysctl
    #   - Get default network interface
    #   - Clear existing iptables rules
    #   - Set iptables default policies to ACCEPT
    #   - Add NAT rule for MASQUERADE
    #   - Add forwarding rules between bridge and default interface

    # Enable IP forwarding
    result = exec_sh("sysctl -w net.ipv4.ip_forward=1")
    print(f"✓ Enabled IP forwarding: {result.stdout.strip()}")

    if TARGET_ARCH == "arm64":
        command = 'gw=$(ip route show | grep "dev eth0" | grep "/" | awk \'{print $1}\' | sed \'s|0/.*|1|\') && echo "ip route add default via $gw dev eth0"'
        exec_sh(command)

    # Get default network interface
    route_result = exec_sh("ip route show default")
    if route_result.stdout.strip() == "":
        route_result = exec_sh("ip route show table all | grep default")
        print(f"🔧 DEBUG: Route result: {route_result.stdout}")

        # Parse the result - might have multiple default routes
        lines = route_result.stdout.strip().split("\n")
        default_iface = None
        for line in lines:
            if line.startswith("default"):
                parts = line.split()
                if "dev" in parts:
                    dev_index = parts.index("dev")
                    default_iface = parts[dev_index + 1]
                    print(f"✓ Detected default interface: {default_iface}")
                    break
        if default_iface is None:
            print("Error: Could not detect default interface")
            return False
    else:
        print(f"🔧 DEBUG: Route result: {route_result.stdout}")
        parts = route_result.stdout.split()
        if len(parts) >= 5:
            default_iface = parts[4]
        else:
            print("Error: Could not parse default interface from route output")
            return False

    # Clear existing iptables rules
    exec_sh("""
        iptables -F
        iptables -t nat -F
        iptables -t mangle -F
        iptables -X
    """)
    print("✓ Cleared existing iptables rules")

    # Set default policies to ACCEPT
    exec_sh("""
        iptables -P FORWARD ACCEPT
        iptables -P INPUT ACCEPT
        iptables -P OUTPUT ACCEPT
    """)
    print("✓ Set default policies to ACCEPT")

    # Add iptables rules for NAT and forwarding
    exec_sh("iptables -t nat -A POSTROUTING -s 10.0.0.0/24 ! -o bridge0 -j MASQUERADE")
    print("✓ Added NAT rule for 10.0.0.0/24")

    exec_sh(f"""iptables -A FORWARD -i bridge0 -o {default_iface} -j ACCEPT
                iptables -A FORWARD -i {default_iface} -o bridge0 -m state --state RELATED,ESTABLISHED -j ACCEPT
                iptables -A FORWARD -i bridge0 -o bridge0 -j ACCEPT""")
    print("✓ Added forwarding rules")

    print("✓ NAT and forwarding setup completed successfully")
    return True


def setup_bridge_network():
    """
    Complete bridge network setup combining interface creation and NAT configuration
    """
    print("Setting up complete bridge network...")

    # Create bridge interface
    if not create_bridge_interface():
        return False

    # Set up NAT and forwarding
    if not setup_nat_forwarding():
        return False

    print("✓ Complete bridge network setup successful!")
    return True


from w2d2_test import test_nat_forwarding
from w2d2_test import test_bridge_network

w2d2_test.setup_bridge_network = setup_bridge_network
w2d2_test.setup_nat_forwarding = setup_nat_forwarding

# Run the tests
test_nat_forwarding()
test_bridge_network()


# %%


def create_container_network(container_id, ip_suffix):
    """
    Create network interface for a specific container

    Args:
        container_id: Unique identifier for the container
        ip_suffix: IP address suffix (e.g., 2 for 10.0.0.2)
    """
    print(f"Creating network for container {container_id}...")

    if os.geteuid() != 0:
        print("⚠ Warning: Network setup requires root privileges")
        print("Critical failure - network setup requires root privileges")
        sys.exit(1)  # Exit the Python process on critical failure
    # TODO: Implement container network creation
    #   - Create veth pair with unique names
    #   - Attach host end to bridge0
    #   - Create network namespace
    #   - Move container end to namespace
    #   - Configure IP address and routing in namespace
    #   - Set up DNS resolution

    short_id = container_id[-8:]
    netns_name = f"isolated_{short_id}"

    # print(f"🔧 DEBUG: Creating isolated namespace:")
    print(f"   Namespace: {netns_name}")
    print(f"   Container ID: {container_id}")

    # Create network namespace and configure loopback
    # print(f"🔧 DEBUG: Creating network namespace {netns_name}...")
    exec_sh(f"""
            ip netns add {netns_name}
            ip netns exec {netns_name} ip link set dev lo up
        """)
    print(f"✓ Created isolated namespace: {netns_name}")
    print(f"✓ Configured loopback interface in {netns_name}")

    # Test that the namespace is isolated (should only have loopback)
    # print(f"🔧 DEBUG: Verifying network isolation...")
    result = exec_sh(f"ip netns exec {netns_name} ip addr show")

    # Count network interfaces (should only be loopback)
    interfaces = len([line for line in result.stdout.split("\n") if ": " in line and "lo:" in line])
    if interfaces == 1:
        print("✓ Network isolation verified: only loopback interface present")
    else:
        print(f"⚠ Warning: Expected 1 interface (loopback), found {interfaces}")

    # Test that external connectivity is blocked
    # print(f"🔧 DEBUG: Testing network isolation...")
    ping_test = exec_sh(f"ip netns exec {netns_name} ping -c 1 -W 1 8.8.8.8", check_retcode=False)
    if ping_test.returncode != 0:
        print("✓ Network isolation confirmed: cannot reach external hosts")
    else:
        print("⚠ Warning: Network isolation may not be working - external ping succeeded")

    # Test loopback connectivity
    # print(f"🔧 DEBUG: Testing loopback connectivity...")
    loopback_test = exec_sh(f"ip netns exec {netns_name} ping -c 1 127.0.0.1", check_retcode=False)
    if loopback_test.returncode == 0:
        print("✓ Loopback connectivity confirmed")
    else:
        print("⚠ Warning: Loopback connectivity failed")

    print(f"✓ Successfully created isolated network namespace: {netns_name}")
    print("  - No external connectivity")
    print("  - Only loopback interface (127.0.0.1)")
    print("  - Complete network isolation")

    return netns_name


def cleanup_container_network(container_id):
    """Clean up network resources for a container"""
    if os.geteuid() != 0:
        print("⚠ Warning: Network cleanup requires root privileges")
        return
    # TODO: Implement container network cleanup
    #   - Remove network namespace
    #   - Remove host veth if it still exists

    short_id = container_id[-8:]
    netns_name = f"isolated_{short_id}"

    # print(f"🔧 DEBUG: Cleaning up isolated namespace for container {container_id}")
    print(f"   Short ID: {short_id}")
    print(f"   Namespace: {netns_name}")

    # Remove network namespace
    # print(f"🔧 DEBUG: Removing network namespace {netns_name}...")
    result = exec_sh(f"ip netns del {netns_name}", check_retcode=False)
    if result.returncode == 0:
        print(f"✓ Removed isolated namespace: {netns_name}")
    else:
        print(f"⚠ Could not remove namespace {netns_name}: {result.stderr}")

    print(f"✓ Isolated network cleanup completed for container {container_id}")


w2d2_test.cleanup_container_network = cleanup_container_network
w2d2_test.create_container_network = create_container_network
from w2d2_test import test_container_network

# Run the test
test_container_network()

# %%


def run_networked_container(cgroup_name, chroot_dir, command=None, memory_limit="100M", container_name="container"):
    """
    Create a new container with full networking support

    Args:
        cgroup_name: Name of the cgroup to create/use
        chroot_dir: Directory to chroot into
        command: Command to run
        memory_limit: Memory limit for the cgroup
        container_name: Name for the container (used in networking)
    """
    # Create cgroup
    create_cgroup(cgroup_name, memory_limit=memory_limit)

    if command is None:
        command = ["/bin/sh"]
    elif isinstance(command, str):
        command = ["/bin/sh", "-c", command]

    # Generate unique container ID
    container_id = f"{container_name}_{str(uuid.uuid4())[:8]}"
    ip_suffix = hash(container_id) % 200 + 50  # IP range 10.0.0.50-249
    # TODO: Implement networked container
    #   - Set up DNS resolution in chroot
    #   - Set up bridge network
    #   - Create container network with unique IP
    #   - Execute command with network namespace
    #   - Clean up network resources
    try:
        chroot_etc_dir = os.path.join(chroot_dir, "etc")
        os.makedirs(chroot_etc_dir, exist_ok=True)

        chroot_resolv_conf = os.path.join(chroot_etc_dir, "resolv.conf")
        with open(chroot_resolv_conf, "w") as f:
            f.write("# DNS configuration for containerized environment\n")
            f.write("nameserver 8.8.8.8\n")
            f.write("nameserver 8.8.4.4\n")
            f.write("nameserver 1.1.1.1\n")
            f.write("options timeout:2 attempts:3\n")
        print("✓ Created working DNS configuration in chroot")
    except Exception as e:
        print(f"⚠ Warning: Could not set up DNS in chroot: {e}")

    # Set up bridge network
    bridge_ready = setup_bridge_network()

    # Create container network
    netns_name = None
    if bridge_ready:
        netns_name = create_container_network(container_id, ip_suffix)
        if netns_name:
            print(f"✓ Container {container_id} assigned IP: 10.0.0.{ip_suffix}/24")
        else:
            print(f"✗ Failed to create network for container {container_id}")
    else:
        print("⚠ Bridge network not ready, container will run with isolated network")

    try:
        # Build execution command
        if netns_name:
            # Execute with dedicated network namespace
            exec_args = [
                "ip",
                "netns",
                "exec",
                netns_name,
                "unshare",
                "--pid",
                "--mount",
                "--uts",
                "--ipc",
                "--fork",
                "chroot",
                chroot_dir,
            ] + command
            # print(f"🔧 DEBUG: Executing with network namespace: {netns_name}")
        else:
            # Execute without network namespace
            exec_args = [
                "unshare",
                "--pid",
                "--mount",
                "--net",
                "--uts",
                "--ipc",
                "--fork",
                "chroot",
                chroot_dir,
            ] + command
            # print(f"🔧 DEBUG: Executing without network namespace")

        print(f"\n🚀 STARTING CONTAINER {container_id}")
        print("=" * 60)

        # Use Popen for real-time output streaming
        process = subprocess.Popen(
            exec_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1,  # Line buffered
        )

        # Stream output in real-time
        if process.stdout:
            while True:
                output = process.stdout.readline()
                if output == "" and process.poll() is not None:
                    break
                if output:
                    print(output.strip())

        # Wait for process to complete
        exit_code = process.wait()

        print("=" * 60)
        print(f"🏁 CONTAINER {container_id} COMPLETED")
        # print(f"🔧 DEBUG: Container exit code: {exit_code}")

        # Cleanup
        if netns_name:
            cleanup_container_network(container_id)

        return exit_code

    except Exception as e:
        print(f"✗ Error running networked container: {e}")
        if netns_name:
            cleanup_container_network(container_id)
        return None


from w2d2_test import test_networked_container

w2d2_test.run_networked_container = run_networked_container

# Run the test
test_networked_container()
