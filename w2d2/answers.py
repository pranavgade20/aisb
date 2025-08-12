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
