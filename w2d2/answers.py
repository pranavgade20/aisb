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
    base_url = 'https://auth.docker.io/token'
    # 1. Initialize empty headers dictionary
    params = ['service=registry.docker.io']
    # 2. Check if registry is Docker Hub (registry-1.docker.io)
    if registry == 'registry-1.docker.io':
    # 3. For Docker Hub, construct token URL with service and scope parameters
        scope = f'repository:{image}:pull'
        params.append(f'scope={scope}')
    # 4. Make HTTP request to auth.docker.io/token
        url = f'{base_url}?{'&'.join(params)}'
        response = requests.get(url)
        # 5. Parse JSON response to extract token
        token = response.json()['token']
        # 6. Add Authorization header with Bearer token
        headers['Authorization'] = f'Bearer {token}'
        # 7. Return headers dictionary
        return headers  # Placeholder return
    
    return {}

from w2d2_test import test_get_auth_token

test_get_auth_token(get_auth_token)

# %%
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
    # 1. Build manifest list URL
    url = f'https://{registry}/v2/{image}/manifests/{tag}'
    # 2. Make HTTP request with headers
    response = requests.get(url, headers=headers).json()
    # 3. Parse JSON response
    manifests = response['manifests']
    for m in manifests:
        platform = m['platform']
        digest = m['digest']
    # 4. Find manifest matching target_arch and target_variant
        if platform.get('architecture') == target_arch and platform.get('variant') == target_variant:
            return digest

    # 5. Return the digest, or raise ValueError if not found
    raise ValueError('Digest not found')
            
from w2d2_test import test_get_target_manifest

test_get_target_manifest(get_target_manifest, get_auth_token)
# %%
