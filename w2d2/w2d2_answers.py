# %%
import json
import os
import platform
import subprocess
import sys
import tarfile
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple, Union

import requests


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
    # TODO: Implement image reference parsing
    # - Check if the image reference starts with 'http' to identify full URLs
    # - For full URLs, remove protocol and split by '/' to extract components
    # - For custom registries, look for dots in the first part (e.g., gcr.io)
    # - For Docker Hub images, default to 'registry-1.docker.io' and add 'library/' prefix if needed
    # - Use rsplit(':', 1) to handle image names that might contain colons
    # - Default to 'latest' tag if none is specified
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

    # e.g. https://registry-1.docker.io/v2/library/hello-world/manifests/latest
    # Get manifest list
    manifest_list_url = f"https://{registry}/v2/{image}/manifests/{tag}"
    print(f"Fetching manifest list from: {manifest_list_url}")

    resp = requests.get(manifest_list_url, headers=headers)
    resp.raise_for_status()
    manifest_list = resp.json()

    # Find the manifest for our target architecture
    target_manifest = None
    for manifest in manifest_list.get("manifests", []):
        platform = manifest.get("platform", {})
        if platform.get("architecture") == target_arch:
            # Check variant if specified
            if target_variant:
                if platform.get("variant") == target_variant:
                    target_manifest = manifest
                    break
            else:
                # No variant specified, take the first match
                target_manifest = manifest
                break

    if not target_manifest:
        available_archs = []
        for manifest in manifest_list.get("manifests", []):
            platform = manifest.get("platform", {})
            arch_str = platform.get("architecture", "unknown")
            if platform.get("variant"):
                arch_str += f" {platform.get('variant')}"
            available_archs.append(arch_str)

        raise ValueError(
            f"No manifest found for architecture {target_arch}"
            f"{f' variant {target_variant}' if target_variant else ''}. "
            f"Available: {', '.join(available_archs)}"
        )

    manifest_digest = target_manifest["digest"]
    print(f"Found manifest for {target_arch}: {manifest_digest}")
    return manifest_digest


# %%
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
    # Get the actual manifest using the digest
    manifest_url = f"https://{registry}/v2/{image}/manifests/{manifest_digest}"
    headers_copy = headers.copy()
    headers_copy["Accept"] = (
        "application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json"
    )

    print(f"Fetching manifest from: {manifest_url}")
    resp = requests.get(manifest_url, headers=headers_copy)
    resp.raise_for_status()
    manifest = resp.json()

    print(f"Manifest type: {manifest.get('mediaType', 'unknown')}")
    layers = manifest.get("layers", [])
    print(f"Number of layers: {len(layers)}")

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
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    for l in layers:
        digest = l["digest"]
        url = f"https://{registry}/v2/{image}/blobs/{digest}"
        resp = requests.get(url, headers=headers, stream=True)
        resp.raise_for_status()

        with tarfile.open(fileobj=BytesIO(resp.content), mode="r:gz") as tar:
            tar.extractall(output_dir)


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
    registry, image, tag = parse_image_reference(image_ref)
    # 2. get_auth_token()
    headers = get_auth_token(registry, image)
    # 3. get_target_manifest()
    manifest_digest = get_target_manifest(registry, image, tag, headers, target_arch, target_variant)
    # 4. get_manifest_layers()
    layers = get_manifest_layers(registry, image, manifest_digest, headers)
    # 5. download_and_extract_layers()
    download_and_extract_layers(registry, image, layers, headers, output_dir)
    print(f"Successfully extracted {image_ref} to {output_dir}")


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
    if command is None:
        handled_command = ["/bin/sh"]
    elif isinstance(command, str):
        handled_command = ["/bin/sh", '-c', command]
    elif isinstance(command, list):
        handled_command = command

    full_command = ["chroot", chroot_dir] + handled_command

    proc = subprocess.run(
        full_command,
        timeout=10,
        capture_output=True,
        text=True,
        timeout=30
    )
    pass
    # if proc.returncode != 0:
    # raise RuntimeError("Command failed")

    return proc


# %%
from w2d2_test import test_run_chroot

# Run the test
test_run_chroot(run_chroot)

# %%
