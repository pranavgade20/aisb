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
        parse_image_reference("hello-world:latest") -> ("mirror.gcr.io", "library/hello-world", "latest")
        parse_image_reference("gcr.io/project/image:v1.0") -> ("gcr.io", "project/image", "v1.0")
        parse_image_reference("https://registry-1.docker.io/v2/library/hello-world/manifests/latest") -> ("registry-1.docker.io", "library/hello-world", "latest")
    """
    if image_ref.startswith('http'):
        parsed_ref = image_ref.replace('http://', '').replace('https://', '')
        registry, rest = parsed_ref.split('/', 1)
        if '/manifests/' in rest:
            image, tag = rest.split('/manifests/')
            return registry, image, tag
        else:
            image, tag = rest.rsplit('/')
            return registry, image, tag
    elif '/' in image_ref:
        registry, rest = image_ref.split('/', 1)
        if '.' in registry:
            if ':' in rest:    
                image, tag = rest.rsplit(':')
            else:
                image, tag = rest, 'latest'
            return registry, image, tag
        else:
            raise KeyError('invalid image reference')
    else:
        registry = "mirror.gcr.io"
        if ':' in image_ref:    
            image, tag = image_ref.rsplit(':')
        else:
            image, tag = image_ref, 'latest'
        image = 'library/' + image
        return registry, image, tag

# %%
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
    base_url = 'https://auth.docker.io/token'
    # 1. Initialize empty headers dictionary
    params = ['service=registry.docker.io']
    # 2. Check if registry is Docker Hub (registry-1.docker.io)
    if registry == 'registry-1.docker.io':
    # 3. For Docker Hub, construct token URL with service and scope parameters
        scope = f'repository:{image}:pull'
        params.append(f'scope={scope}')
    # 4. Make HTTP request to auth.docker.io/token
        url = f'{base_url}?{'&'.join(params)}'
        response = requests.get(url)
        # 5. Parse JSON response to extract token
        token = response.json()['token']
        # 6. Add Authorization header with Bearer token
        headers['Authorization'] = f'Bearer {token}'
        # 7. Return headers dictionary
        return headers  # Placeholder return
    
    return {}

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
    # 1. Build manifest list URL
    url = f'https://{registry}/v2/{image}/manifests/{tag}'
    # 2. Make HTTP request with headers
    response = requests.get(url, headers=headers).json()
    # 3. Parse JSON response
    manifests = response['manifests']
    for m in manifests:
        platform = m['platform']
        digest = m['digest']
    # 4. Find manifest matching target_arch and target_variant
        if platform.get('architecture') == target_arch and platform.get('variant') == target_variant:
            return digest

    # 5. Return the digest, or raise ValueError if not found
    raise ValueError('Digest not found')
            
from w2d2_test import test_get_target_manifest

test_get_target_manifest(get_target_manifest, get_auth_token)

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
    # Get the actual manifest using the digest
    manifest_url = f"https://{registry}/v2/{image}/manifests/{manifest_digest}"
    headers_copy = headers.copy()
    headers_copy['Accept'] = 'application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json'
    
    print(f"Fetching manifest from: {manifest_url}")
    resp = requests.get(manifest_url, headers=headers_copy)
    resp.raise_for_status()
    manifest = resp.json()
    
    print(f"Manifest type: {manifest.get('mediaType', 'unknown')}")
    layers = manifest.get('layers', [])
    print(f"Number of layers: {len(layers)}")
    
    return layers
    
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
    # Step 1: Parse image reference
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

from w2d2_test import test_pull_layers_complete
test_pull_layers_complete(pull_layers)

# %%
pull_layers("alpine:latest", "./extracted_alpine")
pull_layers("python:3.12-alpine", "./extracted_python") 

# %%
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
    # 1. Handle different command formats (None, string, list)
    command_list = []
    if command == None:
        command_list = ['/bin/sh']
    elif type(command) == str:
        command_list = ['/bin/sh', '-c', command]
    elif type(command) == list:
        command_list = command
    # 2. Build the chroot command: ['chroot', chroot_dir] + command
    chroot_command = ['chroot', chroot_dir] + command_list
    # 3. Execute with subprocess.run() with timeout and output capture
    
    result = subprocess.run(chroot_command, capture_output=True, text=True, timeout=30)
    # 4. Print execution details and results
    print(result.stdout)
    # 5. Handle TimeoutExpired and other exceptions
    # 6. Return the result or None on error
    # return output
    if result.stdout:
        print(f"stdout:\n{result.stdout}")
    if result.stderr:
        print(f"stderr:\n{result.stderr}")
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
    # 1. Create a new cgroup directory with path /sys/fs/cgroup/{cgroup_name} - you will write files in this directory to configure the cgroup
    path = f'/sys/fs/cgroup/{cgroup_name}'
    os.makedirs(path, exist_ok=True)
    # 2. Enable controllers (+cpu +memory +pids) in parent cgroup
    with open('/sys/fs/cgroup/cgroup.subtree_control', 'w') as f:
        f.write("+cpu +memory +pids")
    # 3. Set memory limit if specified - write the memory limit to {cgroup_path}/memory.max, which will tell the kernel how much memory the cgroup can use
    if memory_limit:
        with open(f'{path}/memory.max', 'w') as f:
            f.write(f"{str(memory_limit)}")
    # 4. Return the cgroup path
    return path
    # 5. Handle errors and return None on failure

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
    # 1. Use current process PID if none specified
    if pid == None:
        pid = os.getpid()
    # 2. Write PID to cgroup.procs file
    with open(f'/sys/fs/cgroup/{cgroup_name}/cgroup.procs', 'w') as f:
        ok = f.write(f"{pid}")
    # 3. Handle errors and return success status
    return ok

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
    # 1. Create cgroup with memory limit
    create_cgroup(cgroup_name, memory_limit)
    # 2. Handle command format (None, string, list)
    if command is None:
        command = ['/bin/sh']
    elif isinstance(command, str):
        command = ['/bin/sh', '-c', command]
    # 3. Create shell script that:
    #    - Adds process to cgroup
    #    - Executes chroot with command
    script = f"""
    echo $$ > /sys/fs/cgroup/{cgroup_name}/cgroup.procs
    chroot {chroot_dir} {' '.join(command)}
    """
    # 4. Run with timeout and error handling
    result = subprocess.run(['sh', '-c', script], timeout=60)
    return result


from w2d2_test import test_memory_simple
from w2d2_test import test_run_in_cgroup_chroot

test_run_in_cgroup_chroot(run_in_cgroup_chroot, create_cgroup=create_cgroup)

# %%
def create_cgroup_comprehensive_part1(cgroup_name, memory, cpu):
    """
    Create a cgroup with comprehensive settings - Part 1: Basic setup
    
    Args:
        cgroup_name: Name of the cgroup (e.g., 'demo')
        memory_limit: Memory limit (e.g., '100M', '1000000')
        cpu_limit: CPU limit (not implemented yet)
    """
    # 1. Call create_cgroup() with the correct parameters to create the cgroup
    cgroup_path = create_cgroup(cgroup_name, memory_limit=memory, cpu_limit=cpu)
    # 2. Disable swap - search for "swap.max" in https://docs.kernel.org/admin-guide/cgroup-v2.html
    swap_path = f'{cgroup_path}/memory.swap.max'
    with open(swap_path, 'w') as f:
        ok = f.write('0')
    # 3. Return cgroup path or None if critical steps fail
    if ok:
        return cgroup_path

    return None


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
    # 1. Call create_cgroup_comprehensive_part1() 
    cgroup_path = create_cgroup_comprehensive_part1(cgroup_name, memory_limit, cpu_limit)
    # 2. Enable OOM group killing + assign process + set OOM score (see the documentation!)
    oom_group_path = f'{cgroup_path}/memory.oom.group'
    oom_score_path = f'/proc/self/oom_score_adj'

    with open(oom_group_path, 'w') as f:
        f.write('1')

    add_process_to_cgroup(cgroup_name)

    with open(oom_score_path, 'w') as f:
        f.write('500')

    # 3. Return cgroup path
    return cgroup_path

from w2d2_test import test_memory_comprehensive
from w2d2_test import test_create_cgroup_comprehensive

test_create_cgroup_comprehensive(test_memory_comprehensive)

# %%
