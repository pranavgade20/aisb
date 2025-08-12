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
# %load_ext autoreload
# %autoreload 2


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

    colon_splits = image_ref.split(":")
    if len(colon_splits) == 1:
        s = colon_splits[0]
        tag = "latest"
    else:
        s, tag = image_ref.split(":")

    slash_splits = s.split("/")
    if len(slash_splits) == 1:
        registry = "registry-1.docker.io"
        image = "library/" + slash_splits[0]
    else:
        registry = slash_splits[0]
        image = "/".join(slash_splits[1:])

    return registry, image, tag
    # return "registry-1.docker.io", "library/hello-world", "latest"  # Placeholder return


from w2d2_test import test_parse_image_reference

test_parse_image_reference(parse_image_reference)
# %%
# %load_ext autoreload
# %autoreload 2


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
    headers = {}
    # 2. Check if registry is Docker Hub (registry-1.docker.io)
    if registry == "registry-1.docker.io":
        pass
    else:
        pass

    # 3. For Docker Hub, construct token URL with service and scope parameters
    # 4. Make HTTP request to auth.docker.io/token
    url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{image}:pull"
    req = requests.get(url, headers)

    # 5. Parse JSON response to extract token
    js_req = req.json()

    # 6. Add Authorization header with Bearer token
    token = js_req["token"]
    headers["Authorization"] = f"Bearer {token}"

    # 7. Return headers dictionary
    return headers


from w2d2_test import test_get_auth_token

test_get_auth_token(get_auth_token)
"""
https://{registry}/v2/{image}/manifests/{tag}

{
  "manifests": [
    {
      "platform": {"architecture": "amd64"},
      "digest": "sha256:abc123..."
    },
    {
      "platform": {"architecture": "arm64", "variant": "v8"},
      "digest": "sha256:def456..."
    }
  ]
}

"""


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

    return layers  # Placeholder return


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
    output_dict = {}
    # 2. For each layer:
    #    a. Build blob URL using digest
    #    b. Download blob with streaming
    #    c. Extract as gzipped tar to output_dir
    print(len(layers))
    for layer in layers:
        blob_url = f"https://{registry}/v2/{image}/blobs/{layer['digest']}"

        blob_resp = requests.get(blob_url, stream=True, headers=headers)

        tar = tarfile.open(fileobj=BytesIO(blob_resp.content), mode="r:gz")
        tar.extractall(path=output_dir)


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
    registry, image, tag = parse_image_reference(image_ref=image_ref)
    auth_headers = get_auth_token(registry=registry, image=image)
    manifest_ = get_target_manifest(
        registry=registry,
        image=image,
        tag=tag,
        headers=auth_headers,
        target_arch=target_arch,
        target_variant=target_variant,
    )
    layers = get_manifest_layers(registry=registry, image=image, manifest_digest=manifest_, headers=auth_headers)
    download_and_extract_layers(
        registry=registry, image=image, layers=layers, headers=auth_headers, output_dir=output_dir
    )

    pass


from w2d2_test import test_pull_layers_complete

test_pull_layers_complete(pull_layers)


pull_layers("alpine:latest", "./extracted_alpine")
pull_layers("python:3.12-alpine", "./extracted_python")
# %%
