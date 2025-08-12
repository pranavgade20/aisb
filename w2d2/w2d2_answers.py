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
        parse_image_reference("hello-world:latest") -> ("registry-1.docker.io", "library/hello-world", "latest")
        parse_image_reference("gcr.io/project/image:v1.0") -> ("gcr.io", "project/image", "v1.0")
    """
    if image_ref.startswith(("http://", "https://")):
        parts = image_ref.split("://", 1)[1].split("/")
        registry = parts[0]
        if "/manifests/" in image_ref:
            img, tag = "/".join(parts[1:]).split("/manifests/", 1)
        else:
            *img_parts, last = parts[1:]
            if ":" in last:
                last, tag = last.rsplit(":", 1)
            else:
                tag = "latest"
            img = "/".join(img_parts + [last])
        return registry, img, tag

    if "/" in image_ref and "." in image_ref.split("/", 1)[0]:
        registry, image_and_tag = image_ref.split("/", 1)
    else:
        registry = "mirror.gcr.io"
        image_and_tag = image_ref if "/" in image_ref else f"library/{image_ref}"

    if ":" in image_and_tag:
        image, tag = image_and_tag.rsplit(":", 1)
    else:
        image, tag = image_and_tag, "latest"

    return registry, image, tag
    # TODO: Implement image reference parsing
    # - Check if the image reference starts with 'http' to identify full URLs
    # - For full URLs, remove protocol and split by '/' to extract components
    # - For custom registries, look for dots in the first part (e.g., gcr.io)
    # - For Docker Hub images, default to 'registry-1.docker.io' and add 'library/' prefix if needed
    # - Use rsplit(':', 1) to handle image names that might contain colons
    # - Default to 'latest' tag if none is specified

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
    headers = {}
    
    if registry == "registry-1.docker.io":
        url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{image}:pull"
        token = requests.get(url).json()["token"]
        headers["Authorization"] = "Bearer " + token
    
    return headers
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
    url = f"https://{registry}/v2/{image}/manifests/{tag}"
    
    obtained = requests.get(url,headers)
    mani_list = obtained.json()

    target_digest = None
    for mani in mani_list.get('manifests'):
        platform = mani.get('platform')
        if platform.get('architecture') == target_arch:
            if target_variant:
                if platform.get('variant') == target_variant:
                    target_digest = mani
                    break
            else:
                target_digest = mani
                break
    if not target_digest:
            raise ValueError
    return target_digest['digest']
       
from w2d2_test import test_get_target_manifest

test_get_target_manifest(get_target_manifest, get_auth_token)
    # TODO: Implement manifest discovery
    # 1. Build manifest list URL
    # 2. Make HTTP request with headers
    # 3. Parse JSON response
    # 4. Find manifest matching target_arch and target_variant
    # 5. Return the digest, or raise ValueError if not found

# %%
def get_manifest_layers(registry: str, image: str, manifest_digest: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
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
    url = f"https://{registry}/v2/{image}/manifests/{manifest_digest}"

    req_headers = dict(headers)
    print(headers)
    print(req_headers)

    resp = requests.get(url, headers=req_headers)
    data = resp.json()

    layers = data.get("layers")
    return [{"digest": l.get("digest"), "size": l.get("size")} for l in layers if "digest" in l and "size" in l]
    # TODO: Implement manifest processing
    # 1. Build manifest URL using digest
    # 2. Add Accept header for v2 manifest format
    # 3. Make HTTP request
    # 4. Parse JSON and extract layers
    # 5. Return list of layer dictionaries
    return []  # Placeholder return
from w2d2_test import test_get_manifest_layers

test_get_manifest_layers(get_manifest_layers, get_auth_token, get_target_manifest)

# %%

def download_and_extract_layers(registry: str, image: str, layers: List[Dict[str, Any]], 
                               headers: Dict[str, str], output_dir: str) -> None:
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
    pass
from w2d2_test import test_download_and_extract_layers

test_download_and_extract_layers(download_and_extract_layers, get_auth_token, 
                                get_target_manifest, get_manifest_layers)
