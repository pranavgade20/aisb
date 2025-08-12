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
    if "SOLUTION":
        headers = {}
        if registry == "registry-1.docker.io":
            # Get auth token for Docker Hub
            token_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{image}:pull"
            token_resp = requests.get(token_url)
            token_resp.raise_for_status()
            token = token_resp.json()["token"]
            headers["Authorization"] = f"Bearer {token}"
        return headers
    else:
        # TODO: Authentication implementation
        # 1. Initialize empty headers dictionary
        # 2. Check if registry is Docker Hub (registry-1.docker.io)
        # 3. For Docker Hub, construct token URL with service and scope parameters
        # 4. Make HTTP request to auth.docker.io/token
        # 5. Parse JSON response to extract token
        # 6. Add Authorization header with Bearer token
        # 7. Return headers dictionary
        return {}  # Placeholder return


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
    return []  # Placeholder return


from w2d2_test import test_get_manifest_layers

test_get_manifest_layers(get_manifest_layers, get_auth_token, get_target_manifest)
