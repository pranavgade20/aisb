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
