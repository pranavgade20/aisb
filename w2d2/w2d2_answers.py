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

    elif "." not in image_ref:
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

    print(registry)
    print(type(registry))

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

    url = f"https://auth.docker.io/token?service=registry-1.docker.io&scope=repository:{image}:pull"
    response = requests.get(url).json()
    token = response["token"]

    headers = {}
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
