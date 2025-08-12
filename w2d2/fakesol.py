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
    'x86_64': ('amd64', None), 'amd64': ('amd64', None),
    'arm64': ('arm64', 'v8'), 'aarch64': ('arm64', 'v8'),
    'armv7l': ('arm', 'v7'), 'armv6l': ('arm', 'v6')
}.get(platform.machine().lower(), ('amd64', None))

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
    if image_ref.startswith(("http://", "https://")):
        parts = image_ref.split("://", 1)[1].split("/")
        registry = parts[0]
        if "/manifests/" in image_ref:
            img, tag = "/".join(parts[1:]).split("/manifests/", 1)
        else:
            *img_parts, last = parts[1:]
            if ":" in last:
                last, tag = last.rsplit(":", 1)
            else:
                tag = "latest"
            img = "/".join(img_parts + [last])
        return registry, img, tag

    if "/" in image_ref and "." in image_ref.split("/", 1)[0]:
        registry, image_and_tag = image_ref.split("/", 1)
    else:
        registry = "mirror.gcr.io"
        image_and_tag = image_ref if "/" in image_ref else f"library/{image_ref}"

    if ":" in image_and_tag:
        image, tag = image_and_tag.rsplit(":", 1)
    else:
        image, tag = image_and_tag, "latest"

    return registry, image, tag
    # TODO: Implement image reference parsing
    # - Check if the image reference starts with 'http' to identify full URLs
    # - For full URLs, remove protocol and split by '/' to extract components
    # - For custom registries, look for dots in the first part (e.g., gcr.io)
    # - For Docker Hub images, default to 'registry-1.docker.io' and add 'library/' prefix if needed
    # - Use rsplit(':', 1) to handle image names that might contain colons
    # - Default to 'latest' tag if none is specified

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
    # 2. Check if registry is Docker Hub (registry-1.docker.io)
    # 3. For Docker Hub, construct token URL with service and scope parameters
    # 4. Make HTTP request to auth.docker.io/token
    # 5. Parse JSON response to extract token
    # 6. Add Authorization header with Bearer token
    # 7. Return headers dictionary
    headers = {}
    
    if registry == "registry-1.docker.io":
        url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{image}:pull"
        token = requests.get(url).json()["token"]
        headers["Authorization"] = "Bearer " + token
    
    return headers
from w2d2_test import test_get_auth_token

test_get_auth_token(get_auth_token)

# %%

def get_target_manifest(registry: str, image: str, tag: str, headers: Dict[str, str], 
                       target_arch: str, target_variant: Optional[str] = None) -> str:
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
    url = f"https://{registry}/v2/{image}/manifests/{tag}"
    
    obtained = requests.get(url,headers)
    mani_list = obtained.json()

    target_digest = None
    for mani in mani_list.get('manifests'):
        platform = mani.get('platform')
        if platform.get('architecture') == target_arch:
            if target_variant:
                if platform.get('variant') == target_variant:
                    target_digest = mani
                    break
            else:
                target_digest = mani
                break
    if not target_digest:
            raise ValueError
    return target_digest['digest']
       
from w2d2_test import test_get_target_manifest

test_get_target_manifest(get_target_manifest, get_auth_token)
    # TODO: Implement manifest discovery
    # 1. Build manifest list URL
    # 2. Make HTTP request with headers
    # 3. Parse JSON response
    # 4. Find manifest matching target_arch and target_variant
    # 5. Return the digest, or raise ValueError if not found

# %%
def get_manifest_layers(registry: str, image: str, manifest_digest: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
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

    req_headers = dict(headers)
    print(headers)
    print(req_headers)

    resp = requests.get(url, headers=req_headers)
    data = resp.json()

    layers = data.get("layers")
    return [{"digest": l.get("digest"), "size": l.get("size")} for l in layers if "digest" in l and "size" in l]
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

def download_and_extract_layers(registry: str, image: str, layers: List[Dict[str, Any]], 
                               headers: Dict[str, str], output_dir: str) -> None:
    """
    Download and extract all layers to the output directory.
    
    Args:
        registry: Registry hostname
        image: Image name
        layers: List of layer dictionaries from manifest
        headers: Authentication headers
        output_dir: Directory to extract layers to
    """
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Download and extract layers in order
    for i, layer in enumerate(layers):
        digest = layer['digest']
        size = layer.get('size', 0)
        print(f"\nProcessing layer {i + 1}/{len(layers)}: {digest} ({size} bytes)")

        # Download layer blob
        blob_url = f"https://{registry}/v2/{image}/blobs/{digest}"
        blob_resp = requests.get(blob_url, headers=headers, stream=True)
        blob_resp.raise_for_status()

        # Extract layer (layers are gzipped tarballs)
        print(f"  Extracting to {output_dir}...")
        with tarfile.open(fileobj=BytesIO(blob_resp.content), mode='r:gz') as tar:
            tar.extractall(output_dir)

    print(f"\n✓ Extracted {len(layers)} layers to {output_dir}")
    # TODO: Implement layer download and extraction
    # 1. Create output directory
    # 2. For each layer:
    #    a. Build blob URL using digest
    #    b. Download blob with streaming
    #    c. Extract as gzipped tar to output_dir
    # 3. Print progress information
    pass
from w2d2_test import test_download_and_extract_layers

test_download_and_extract_layers(download_and_extract_layers, get_auth_token, 
                                get_target_manifest, get_manifest_layers)

# %%
def pull_layers(image_ref: str, output_dir: str, target_arch: str = TARGET_ARCH, 
                target_variant: Optional[str] = TARGET_VARIANT) -> None:
    """
    Pull and extract Docker image layers for a specific architecture.
    
    Args:
        image_ref: Docker image reference (various formats supported)
        output_dir: Directory to extract layers to
        target_arch: Target architecture (default: auto-detected)
        target_variant: Target architecture variant (default: auto-detected)
    """
    registry, image, tag = parse_image_reference(image_ref)
    
    print(f"Registry: {registry}")
    print(f"Image: {image}")
    print(f"Tag: {tag}")
    print(f"Target architecture: {target_arch}{f' variant {target_variant}' if target_variant else ''}")
    
    # Step 2: Get authentication
    headers = get_auth_token(registry, image)
    
    # Step 3: Get target manifest
    manifest_digest = get_target_manifest(registry, image, tag, headers, target_arch, target_variant)
    
    # Step 4: Get layers from manifest
    layers = get_manifest_layers(registry, image, manifest_digest, headers)
    
    # Step 5: Download and extract layers
    download_and_extract_layers(registry, image, layers, headers, output_dir)
    
    print(f"✓ Successfully extracted {image_ref} to {output_dir}")
    print(f"  Architecture: {target_arch}{f' variant {target_variant}' if target_variant else ''}")
    # TODO: Implement complete pull_layers function
    # Use all the functions you've implemented above:
    # 1. parse_image_reference()
    # 2. get_auth_token()
    # 3. get_target_manifest()
    # 4. get_manifest_layers()
    # 5. download_and_extract_layers()
    pass
from w2d2_test import test_pull_layers_complete

test_pull_layers_complete(pull_layers)

# %%
'''
import subprocess

def run_chroot(chroot_dir: str, command: Optional[Union[str, List[str]]] = None) -> Optional[subprocess.CompletedProcess]:
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
    
    # TODO: Implement chroot command execution
    # 1. Handle different command formats (None, string, list)
    # 2. Build the chroot command: ['chroot', chroot_dir] + command
    # 3. Execute with subprocess.run() with timeout and output capture
    # 4. Print execution details and results
    # 5. Handle TimeoutExpired and other exceptions
    # 6. Return the result or None on error
    if command is None:
        command = ['/bin/sh']
    elif isinstance(command, str):
        command = ['/bin/sh', '-c', command]
    
    print(f"Running chroot {chroot_dir} with command: {' '.join(command)}")
    
    result = subprocess.run(['chroot', chroot_dir] + command,
                            capture_output=True, text=True, timeout=30)
    print(f"Exit code: {result.returncode}")
    if result.stdout:
        print(f"stdout:\n{result.stdout}")
    if result.stderr:
        print(f"stderr:\n{result.stderr}")
    return result

from w2d2_test import test_run_chroot
# Run the test
test_run_chroot(run_chroot)
'''

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
    try:
        path = f"/sys/fs/cgroup/{cgroup_name}"
        os.makedirs(path, exist_ok=True)
        with open("/sys/fs/cgroup/cgroup.subtree_control", "a") as file:
            file.write("+cpu +memory +pids\n")
        if memory_limit:
            with open(f"{path}/memory.max", "w") as file:
                file.write(str(memory_limit))
        return path
    except Exception as e:
        print(e)
        return None

    # TODO: Implement basic cgroup creation
    # 1. Create a new cgroup directory with path /sys/fs/cgroup/{cgroup_name} - you will write files in this directory to configure the cgroup
    # 2. Enable controllers (+cpu +memory +pids) in parent cgroup
    # 3. Set memory limit if specified - write the memory limit to {cgroup_path}/memory.max, which will tell the kernel how much memory the cgroup can use
    # 4. Return the cgroup path
    # 5. Handle errors and return None on failure
from w2d2_test import test_create_cgroup

test_create_cgroup(create_cgroup)

def add_process_to_cgroup(cgroup_name, pid=None):
    """
    Add a process to a cgroup
    
    Args:
        cgroup_name: Name of the cgroup
        pid: Process ID (default: current process)
    """
    if pid is None:
        pid = os.getpid()
    procs_path = f"/sys/fs/cgroup/{cgroup_name}/cgroup.procs"

    with open(procs_path,'w') as file:
        file.write(str(pid))
    return True
    # TODO: Implement process assignment to cgroup
    # 1. Use current process PID if none specified
    # 2. Write PID to cgroup.procs file
    # 3. Handle errors and return success status
    pass
from w2d2_test import test_add_process_to_cgroup

'''
test_add_process_to_cgroup(add_process_to_cgroup, create_cgroup)

def run_in_cgroup_chroot(cgroup_name, chroot_dir, command=None, memory_limit="100M"):
    """
    Run a command in both a cgroup and chroot environment
    
    Args:
        cgroup_name: Name of the cgroup to create/use
        chroot_dir: Directory to chroot into
        command: Command to run
        memory_limit: Memory limit for the cgroup
    """
    create_cgroup(cgroup_name,memory_limit=memory_limit)
    if command is None:
        command = ['/bin/sh']
        print(command)
    elif isinstance(command, str):
        command = ['/bin/sh', '-c', command]
        print(command)
    
    script = f"""
    echo $$ > /sys/fs/cgroup/{cgroup_name}/cgroup.procs
    chroot {chroot_dir} {' '.join(command)}
    """

    result = subprocess.run(['sh', '-c', script], timeout=60)
    return result
    # TODO: Implement combined cgroup-chroot execution
    # 1. Create cgroup with memory limit
    # 2. Handle command format (None, string, list)
    # 3. Create shell script that:
    #    - Adds process to cgroup
    #    - Executes chroot with command
    # 4. Run with timeout and error handling
    pass
from w2d2_test import test_memory_simple
from w2d2_test import test_run_in_cgroup_chroot

test_run_in_cgroup_chroot(run_in_cgroup_chroot)'''

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
    cgroup_path = create_cgroup(cgroup_name, memory_limit=memory, cpu_limit=cpu)
    try:
        swap_max_path = f"{cgroup_path}/memory.swap.max"
        with open(swap_max_path, "w") as file:
            file.write("0")
    except Exception as e:
        print(e)
    
    return cgroup_path
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
    cgroup_path = create_cgroup_comprehensive_part1(cgroup_name, memory_limit, cpu_limit)
    if not cgroup_path:
        return None
    try:
        with open(f"{cgroup_path}/memory.oom.group", "w") as f:
            f.write("1")
    except Exception as e:
        print(e)
    try:
        with open(f"{cgroup_path}/cgroup.procs", "w") as f:
            f.write(str(os.getpid()))
    except Exception as e:
        print(e)
    try:
        with open("/proc/self/oom_score_adj", "w") as ile:
            file.write("500")
    except Exception as e:
        print(e)
    return cgroup_path
    # TODO: Part 2 implementation
    # 1. Call create_cgroup_comprehensive_part1() 
    # 2. Enable OOM group killing + assign process + set OOM score (see the documentation!)
    # 3. Return cgroup path
    pass
from w2d2_test import test_memory_comprehensive
from w2d2_test import test_create_cgroup_comprehensive

test_create_cgroup_comprehensive(test_memory_comprehensive)

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
        command = ['/bin/sh']
    elif isinstance(command, str):
        command = ['/bin/sh', '-c', command]
    
    print(f"Running `{command}` in cgroup {cgroup_name} with chroot {chroot_dir} and namespaces")

    pid = os.fork()
        
    if pid == 0:
        # CHILD PROCESS EXECUTION PATH
        
        # Step 2: Set up signal handler to receive SIGUSR1 from parent
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
            subprocess.run([
                'unshare',
                '--pid',    # Process ID namespace isolation
                '--mount',  # Mount namespace isolation  
                '--net',    # Network namespace isolation
                '--uts',    # Hostname namespace isolation
                '--ipc',    # IPC namespace isolation
                '--fork',   # Fork after creating namespaces
                'chroot', chroot_dir  # Change root directory
            ] + command, check=True)
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
    
from w2d2_test import test_namespace_isolation

test_namespace_isolation() 
    # TODO: Implement namespace isolation following these steps:
    
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

# %%
