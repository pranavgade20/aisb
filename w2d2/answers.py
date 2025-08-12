#%%


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

#%%

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
    # default_registry = "registry-1.docker.io"
    default_registry = "mirror.gcr.io"
    default_tag = 'latest'
    if image_ref.startswith('http'): 
        protocol, image_ref = image_ref.split('://')

    splitted = image_ref.split('/')
    if '.' in splitted[0]:
        registry = splitted[0]
        splitted = splitted[1:]
    else:
        registry = default_registry
    image_and_tag = '/'.join(splitted).rsplit(':', 1)
    if len(image_and_tag) == 2:
        image, tag = image_and_tag
    else:
        image, tag = image_and_tag[0], default_tag
    if '/' not in image:
        image = f'library/{image}'

    return registry, image, tag
        
    
from w2d2_test import test_parse_image_reference

test_parse_image_reference(parse_image_reference)

#%%

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
    if registry == 'registry-1.docker.io':
        # Get auth token for Docker Hub
        token_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{image}:pull"
        token_resp = requests.get(token_url)
        token_resp.raise_for_status()
        token = token_resp.json()['token']
        headers['Authorization'] = f'Bearer {token}'
    return headers

from w2d2_test import test_get_auth_token

test_get_auth_token(get_auth_token)

#%%


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
    # TODO: Implement manifest discovery
    # 1. Build manifest list URL
    # 2. Make HTTP request with headers
    # 3. Parse JSON response
    # 4. Find manifest matching target_arch and target_variant
    # 5. Return the digest, or raise ValueError if not found
    manifest_url = f'https://{registry}/v2/{image}/manifests/{tag}'
    r = requests.get(manifest_url, headers=headers)
    if r.status_code != 200:
        raise ValueError
    parsed = r.json()
    for manifest in parsed['manifests']:
        if manifest['platform']['architecture'] == target_arch and (target_variant is None or target_variant == manifest['platform']['variant']):
            return manifest['digest']
    raise ValueError
                                                                    

from w2d2_test import test_get_target_manifest

test_get_target_manifest(get_target_manifest, get_auth_token)

#%%

