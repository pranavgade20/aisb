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
import re


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
    # Full registry URLs: https://registry-1.docker.io/v2/library/hello-world/manifests/latest
    # Docker Hub format: hello-world:latest or library/hello-world:latest
    # Custom registries: gcr.io/google-containers/pause:latest

    # TODO: Implement image reference parsing
    # - Check if the image reference starts with 'http' to identify full URLs
    # - For full URLs, remove protocol and split by '/' to extract components
    # - For custom registries, look for dots in the first part (e.g., gcr.io)
    # - For Docker Hub images, default to 'registry-1.docker.io' and add 'library/' prefix if needed
    # - Use rsplit(':', 1) to handle image names that might contain colons
    # - Default to 'latest' tag if none is specified
    if ":" not in image_ref:
        registry = "registry-1.docker.io"
        image = image_ref
        if "library" not in image:
            image = "library/" + image
        tag = "latest"
    elif "http" in image_ref:
        registry = image_ref.split("/")[2]
        image = "/".join(image_ref.split("/")[4:6])
        tag = image_ref.split("/")[-1]

    elif "." not in image_ref.split(":")[0]:
        registry = "registry-1.docker.io"
        image = image_ref.split(":")[0]
        if "library" not in image:
            image = "library/" + image
        tag = image_ref.split(":")[-1]
    else:
        registry = image_ref.split("/")[0]
        image = "/".join(image_ref.split("/")[1:3])
        image = image.split(":")[0]
        tag = image_ref.split(":")[-1]

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
    # 2. Check if registry is Docker Hub (registry-1.docker.io)
    # 3. For Docker Hub, construct token URL with service and scope parameters
    # 4. Make HTTP request to auth.docker.io/token
    # 5. Parse JSON response to extract token
    # 6. Add Authorization header with Bearer token
    # 7. Return headers dictionary

    headers = {}
    if registry == "registry-1.docker.io":
        # Get auth token for Docker Hub
        token_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{image}:pull"
        token_resp = requests.get(token_url)
        token_resp.raise_for_status()
        token = token_resp.json()["token"]
        headers["Authorization"] = f"Bearer {token}"

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
    # TODO: Implement manifest discovery
    # 1. Build manifest list URL
    # 2. Make HTTP request with headers
    # 3. Parse JSON response
    # 4. Find manifest matching target_arch and target_variant
    # 5. Return the digest, or raise ValueError if not found

    url = f"https://{registry}/v2/{image}/manifests/{tag}"
    response = requests.get(url).json()

    for manifest in response["manifests"]:
        platform = manifest["platform"]

        if "variant" not in platform:
            platform["variant"] = None

        if platform["architecture"] == target_arch and platform["variant"] == target_variant:
            return manifest["digest"]

    raise ValueError()


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
    # 2. Add Accept header for v2 manifest format
    # 3. Make HTTP request
    # 4. Parse JSON and extract layers
    # 5. Return list of layer dictionaries
    url = f"https://{registry}/v2/{image}/manifests/{manifest_digest}"

    accept_header = "application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json"

    headers["Accept"] = accept_header

    response = requests.get(url, headers=headers)
    response = response.json()

    if "layers" not in response:
        return []
    else:
        layers = response["layers"]

    return layers


from w2d2_test import test_get_manifest_layers

test_get_manifest_layers(get_manifest_layers, get_auth_token, get_target_manifest)

# %%


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
    # 1. Create output directory
    # 2. For each layer:
    #    a. Build blob URL using digest
    #    b. Download blob with streaming
    #    c. Extract as gzipped tar to output_dir
    # 3. Print progress information
    if output_dir not in os.listdir():
        os.mkdir(output_dir)

    for layer in layers:
        digest = layer["digest"]
        url = f"https://{registry}/v2/{image}/blobs/{digest}"

        response = requests.get(url, headers=headers)

        bytes_blob = BytesIO(response.content)
        tar_file = tarfile.open(fileobj=bytes_blob, mode="r:gz")
        tar_file.extractall(output_dir)


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
    registry = "mirror.gcr.io"
    headers = get_auth_token(registry, image)
    digest = get_target_manifest(registry, image, tag, headers, target_arch, target_variant)
    layers = get_manifest_layers(registry, image, digest, headers)
    download_and_extract_layers(registry, image, layers, headers, output_dir)


from w2d2_test import test_pull_layers_complete

test_pull_layers_complete(pull_layers)

# %%
pull_layers("alpine:latest", "./extracted_alpine")
pull_layers("python:3.12-alpine", "./extracted_python")

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
    # TODO: Implement chroot command execution
    # 1. Handle different command formats (None, string, list)
    # 2. Build the chroot command: ['chroot', chroot_dir] + command
    # 3. Execute with subprocess.run() with timeout and output capture
    # 4. Print execution details and results
    # 5. Handle TimeoutExpired and other exceptions
    # 6. Return the result or None on error

    if isinstance(command, str):
        chroot_command = ['sudo', 'chroot', chroot_dir, '/bin/sh', '-c', command]
    elif isinstance(command, list):
        chroot_command = ["sudo", "chroot", chroot_dir] + command
    elif command is None:
        chroot_command = ["sudo", "chroot", chroot_dir, "/bin/sh"]

    print(chroot_command)
    try:
        out = subprocess.run(chroot_command, timeout=2, capture_output=True, text=True)
    except TimeoutError as e:
        print(e)
        return None

    return out


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
    # TODO: Implement basic cgroup creation
    # 1. Create a new cgroup directory with path /sys/fs/cgroup/{cgroup_name} - you will write files in this directory to configure the cgroup
    # 2. Enable controllers (+cpu +memory +pids) in parent cgroup
    # 3. Set memory limit if specified - write the memory limit to {cgroup_path}/memory.max, which will tell the kernel how much memory the cgroup can use
    # 4. Return the cgroup path
    # 5. Handle errors and return None on failure
    # path = f'/sys/fs/cgVroup/{cgroup_name}'
    # subprocess.run(['sudo', 'chmod', '+w', '/sys/fs/cgroup/'])
    # os.mkdir(path)
    
    # # subprocess.run(['sudo', 'mkdir', path])

    # with open(path+'/cgroup.subtree_control', 'w') as f:
    #     f.write('+cpu +memory +pids')

    # if memory_limit is not None:
    #     with open(path+'/memory.max', 'w') as f:
    #         f.write(memory_limit)

    # if cpu_limit is not None:
    #     with open(path+'/cpu.max', 'w') as f:
    #         f.write(cpu_limit)

    # return path

    cgroup_path = f"/sys/fs/cgroup/{cgroup_name}"
        
    # Create cgroup directory
    os.makedirs(cgroup_path, exist_ok=True)
    print(f"Created cgroup directory: {cgroup_path}")
        
    # Enable controllers in parent cgroup
    with open("/sys/fs/cgroup/cgroup.subtree_control", "w") as f:
        f.write("+cpu +memory +pids")
    print("Enabled cgroup controllers")
        
    # Set memory limit if specified
    if memory_limit:
        memory_max_path = f"{cgroup_path}/memory.max"
        with open(memory_max_path, "w") as f:
            f.write(str(memory_limit))
        print(f"Set memory limit to {memory_limit}")
    return cgroup_path

from w2d2_test import test_create_cgroup

test_create_cgroup(create_cgroup)

# %%
