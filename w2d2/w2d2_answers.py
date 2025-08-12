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


def parse_image_reference(image_ref: str) -> Tuple[str, str, str]:
    # TODO: Implement image reference parsing
    # - Check if the image reference starts with 'http' to identify full URLs

    # Deal with Full registry URLs
    if image_ref[0:4] == "http":
        # split by '/'
        components = image_ref.replace("https://", "").replace("http://", "").split("/")
        registry = components[0]

        # extract metadata about image
        if "/manifests/" in image_ref:
            parts = "/".join(components[2:]).split("/manifests")
            image = parts[0]
            tag = image[1]
        else:
            image = "/".join(components[1:-1])
            tag = components[-1] if ":" in components[-1] else "latest"

    # Deal with Docker image format (e.g., "hello-world:latest" or "gcr.io/project/image:tag")
    else:
        # Deal with custom registries
        if "/" in image_ref and image_ref.split("/")[0].count(".") > 0:
            components = image_ref.split("/", 1)
            registry = components[0]
            image_and_tag = components[1]

        # Docker Hub
        else:
            registry = "mirror.gcr.io"  # Default to Docker Hub mirror
            image_and_tag = image_ref

            if "/" not in image_and_tag:
                image_and_tag = f"library/{image_and_tag}"

        if ":" in image_and_tag:
            image, tag = image_and_tag.rsplit(":", 1)
        else:
            image = image_and_tag
            tag = "latest"

    # - For full URLs, remove protocol and split by '/' to extract components
    if "/" in image_ref:
        components = image_ref[4:].split("/")
    else:
        components = image_ref[4:].split("/")

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
    headers = {}
    if registry == "registry-1.docker.io":
        # Get auth token for Docker Hub
        token_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{image}:pull"
        token_resp = requests.get(token_url)
        token_resp.raise_for_status()
        token = token_resp.json()["token"]
        headers["Authorization"] = f"Bearer {token}"
    return headers


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
    manifest_url = "https://" + registry + "/v2/" + image + "/manifests/" + tag
    resp = requests.get(manifest_url, headers=headers)
    resp.raise_for_status()
    response = resp.json()

    for manifest in response["manifests"]:
        if manifest["platform"]["architecture"] == target_arch:
            if target_variant is None:
                print("digest: " + manifest["digest"])
                return manifest["digest"]
            else:
                # if manifest["platform"].get("variant") == target_variant:
                if "variant" in manifest["platform"] and manifest["platform"]["variant"] == target_variant:
                    return manifest["digest"]
    raise ValueError


# %%

from w2d2_test import test_get_target_manifest

test_get_target_manifest(get_target_manifest, get_auth_token)


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


# %%
def get_manifest_layers(
    registry: str, image: str, manifest_digest: str, headers: Dict[str, str]
) -> List[Dict[str, Any]]:
    # TODO: Implement manifest processing
    # 1. Build manifest URL using digest
    url = f"https://{registry}/v2/{image}/manifests/{manifest_digest}"
    # 2. Add Accept header for v2 manifest format
    headers["Accept"] = (
        "application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json"
    )
    # 3. Make HTTP request
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    # 4. Parse JSON and extract layers
    layers = response.json()["layers"]
    # 5. Return list of layer dictionaries
    return layers  # Placeholder return


from w2d2_test import test_get_manifest_layers

test_get_manifest_layers(get_manifest_layers, get_auth_token, get_target_manifest)

# %%


def download_and_extract_layers(
    registry: str, image: str, layers: List[Dict[str, Any]], headers: Dict[str, str], output_dir: str
) -> None:
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Download and extract layers in order
    for i, layer in enumerate(layers):
        digest = layer["digest"]
        size = layer.get("size", 0)
        print(f"\nProcessing layer {i + 1}/{len(layers)}: {digest} ({size} bytes)")

        # Download layer blob
        blob_url = f"https://{registry}/v2/{image}/blobs/{digest}"
        blob_resp = requests.get(blob_url, headers=headers, stream=True)
        blob_resp.raise_for_status()

        # Extract layer (layers are gzipped tarballs)
        print(f"  Extracting to {output_dir}...")
        with tarfile.open(fileobj=BytesIO(blob_resp.content), mode="r:gz") as tar:
            tar.extractall(output_dir)

    print(f"\n✓ Extracted {len(layers)} layers to {output_dir}")


from w2d2_test import test_download_and_extract_layers

# test_download_and_extract_layers(download_and_extract_layers, get_auth_token, get_target_manifest, get_manifest_layers)


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

# test_pull_layers_complete(pull_layers)


# %%

import subprocess

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


def run_chroot(
    chroot_dir: str, command: Optional[Union[str, List[str]]] = None
) -> Optional[subprocess.CompletedProcess]:
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
# test_run_chroot(run_chroot)

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

    try:
        output_dir = f"/sys/fs/cgroup/{cgroup_name}"
        os.makedirs(output_dir, exist_ok=True)

        with open("/sys/fs/cgroup/cgroup.subtree_control", "w") as file:
            file.write("+cpu +memory +pids")

        if memory_limit:
            with open(f"{output_dir}/memory.max", "w") as file:
                file.write(str(memory_limit))

        return output_dir

    except Exception as e:
        print(e)
        return None


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
    # TODO: Implement process assignment to cgroup
    # 1. Use current process PID if none specified
    # 2. Write PID to cgroup.procs file
    # 3. Handle errors and return success status
    try:
        output_dir = f"/sys/fs/cgroup/{cgroup_name}"

        if pid:
            with open(f"{output_dir}/cgroup.procs", "w") as file:
                file.write(str(pid))
        else:
            with open(f"{output_dir}/cgroup.procs", "w") as file:
                file.write(str(os.getpid()))
        return True

    except Exception as e:
        print(e)
        return False


from w2d2_test import test_add_process_to_cgroup

test_add_process_to_cgroup(add_process_to_cgroup, create_cgroup)
# %%

"""
Run a command in both a cgroup and chroot environment

Args:
    cgroup_name: Name of the cgroup to create/use
    chroot_dir: Directory to chroot into
    command: Command to run
    memory_limit: Memory limit for the cgroup
"""


def run_in_cgroup_chroot(cgroup_name, chroot_dir, command=None, memory_limit="100M"):
    # TODO: Implement combined cgroup-chroot execution
    # 1. Create cgroup with memory limit
    create_cgroup(cgroup_name, memory_limit=memory_limit)
    # 2. Handle command format (None, string, list)
    # 3. Create shell script that:
    #    - Adds process to cgroup
    add_process_to_cgroup(cgroup_name)
    #    - Executes chroot with command
    run_chroot(chroot_dir, command)
    # 4. Run with timeout and error handling


from w2d2_test import test_memory_simple
from w2d2_test import test_run_in_cgroup_chroot

test_run_in_cgroup_chroot(run_in_cgroup_chroot)
