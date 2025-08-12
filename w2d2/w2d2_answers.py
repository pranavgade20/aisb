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
