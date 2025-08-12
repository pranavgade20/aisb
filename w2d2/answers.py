#%%

import requests
import tarfile
import json
import sys
import os
import platform
from io import BytesIO
from typing import Optional, List, Union, Tuple, Dict, Any
import subprocess

from w2d2.w2d2_test import test_pull_layers_complete

SOLUTION=True

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
"""
### Exercise 1.1: Image Reference Parsing

Parse different Docker image reference formats and extract registry, image, and tag components.

Docker images can be referenced in multiple formats:
- Full registry URLs: `https://registry-1.docker.io/v2/library/hello-world/manifests/latest`
- Docker Hub format: `hello-world:latest` or `library/hello-world:latest` 
- Custom registries: `gcr.io/google-containers/pause:latest`

<details>
<summary>Vocabulary: Docker Image References</summary>

- **Registry**: The server that stores Docker images (e.g., `registry-1.docker.io` for Docker Hub)
- **Repository**: A collection of related images with the same name but different tags (e.g., `ubuntu`)
- **Tag**: A label that points to a specific version of an image (defaults to "latest")
- **Manifest**: Metadata about an image including its layers and configuration
- **Docker Hub**: Docker's official public registry, used as default when no registry is specified

</details>

#### Exercise - implement parse_image_reference

> **Difficulty**: 🔴🔴⚪⚪⚪  
> **Importance**: 🔵🔵🔵⚪⚪
> 
> You should spend up to ~15 minutes on this exercise.

Implement the `parse_image_reference` function that parses different image reference formats.
"""

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
    if "SOLUTION":
        # Parse image reference
        if image_ref.startswith('http'):
            # Full URL provided
            parts = image_ref.replace('https://', '').replace('http://', '').split('/')
            registry = parts[0]
            if '/manifests/' in image_ref:
                # Extract image and tag from URL
                image_parts = '/'.join(parts[2:]).split('/manifests/')
                image = image_parts[0]
                tag = image_parts[1]
            else:
                image = '/'.join(parts[1:-1])
                tag = parts[-1] if ':' in parts[-1] else 'latest'
        else:
            # Docker image format (e.g., "hello-world:latest" or "gcr.io/project/image:tag")
            if '/' in image_ref and image_ref.split('/')[0].count('.') > 0:
                # Custom registry (e.g., gcr.io/project/image)
                parts = image_ref.split('/', 1)
                registry = parts[0]
                image_and_tag = parts[1]
            else:
                # Docker Hub
                registry = 'mirror.gcr.io'  # Default to Docker Hub mirror
                image_and_tag = image_ref
                if '/' not in image_and_tag:
                    image_and_tag = f"library/{image_and_tag}"

            if ':' in image_and_tag:
                image, tag = image_and_tag.rsplit(':', 1)
            else:
                image = image_and_tag
                tag = 'latest'

        return registry, image, tag
    else:
        # TODO: Implement image reference parsing
        # - Check if the image reference starts with 'http' to identify full URLs
        # - For full URLs, remove protocol and split by '/' to extract components
        # - For custom registries, look for dots in the first part (e.g., gcr.io)
        # - For Docker Hub images, default to 'registry-1.docker.io' and add 'library/' prefix if needed
        # - Use rsplit(':', 1) to handle image names that might contain colons
        # - Default to 'latest' tag if none is specified
        return "registry-1.docker.io", "library/hello-world", "latest"  # Placeholder return

"""
<details>
<summary>Hints</summary>
- Step 1: Check if image_ref starts with 'http' or 'https'
  - If yes: Remove protocol, split by '/', extract registry from first part
  - If '/manifests/' in URL: split image_parts by '/manifests/' to get image and tag
  - If no '/manifests/': image is middle parts joined, tag is last part (or 'latest')

- Step 2: For non-URL formats, detect custom registry vs Docker Hub
  - If '/' in image_ref AND first part contains dots: it's a custom registry
  - Split by '/' once: registry = first part, image_and_tag = second part
  - If no custom registry detected: registry = 'registry-1.docker.io', image_and_tag = image_ref

- Step 3: Handle Docker Hub library prefix
  - If using Docker Hub and no '/' in image_and_tag: prefix with "library/"

- Step 4: Extract image and tag from image_and_tag
  - Use rsplit(':', 1) to split on rightmost colon (handles images with colons in name)
  - If no colon found: tag defaults to 'latest'

- Step 5: Return tuple (registry, image, tag)

- Key edge cases to handle:
  - "hello-world" → ("registry-1.docker.io", "library/hello-world", "latest")
  - "ubuntu:20.04" → ("registry-1.docker.io", "library/ubuntu", "20.04")  
  - "gcr.io/project/image:tag" → ("gcr.io", "project/image", "tag")
  - "my-registry.com/org/repo" → ("my-registry.com", "org/repo", "latest")
</details>
"""

# %%
"""
### Exercise 1.2: Docker Registry Authentication (Optional)

> **Difficulty**: 🔴🔴⚪⚪⚪  
> **Importance**: 🔵🔵🔵⚪⚪
> 
> You should spend up to ~10 minutes on this exercise.


Implement authentication with Docker registries using token-based authentication.

Docker registries require authentication to access images. Docker Hub uses a token-based 
authentication system where you request a token for a specific repository scope. Learn more about the [Docker Registry HTTP API v2](https://docs.docker.com/registry/spec/api/) and [Docker Hub authentication flow](https://docs.docker.com/docker-hub/access-tokens/).

The authentication flow:
1. Request a token from the auth server
2. Include the token in subsequent API requests  
3. Token includes scope for specific repository access

<details>
<summary>Vocabulary: Docker Registry Authentication</summary>

- **Bearer Token**: A type of access token that grants access to specific resources to whoever possesses it, without requiring additional proof of identity
- **Scope**: Defines what actions the token allows (e.g., `repository:image:pull`)
- **Auth Server**: The server that issues tokens (auth.docker.io for Docker Hub)
- **Registry Server**: The server that stores actual image data (registry-1.docker.io)
- **Authorization Header**: HTTP header that contains the Bearer token

</details>

**API Usage Instructions:**

Docker Hub uses token-based authentication for accessing private repositories and rate limiting. Here's how to get authentication tokens:

**1. Building the Authentication URL**

Docker Hub's authentication service uses a specific URL format:
- Format: `https://auth.docker.io/token?service=registry.docker.io&scope=repository:{image}:pull`
- Example: `https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/hello-world:pull`
- **What it does**: Requests a token with specific permissions for a repository

**2. Understanding Token Scopes**
- **service**: Always `registry.docker.io` for Docker Hub
- **scope**: Defines permissions in format `repository:{image}:pull`
- **pull**: Permission type (pull, push, delete)

**3. Token Response Format**

The API returns JSON with the token:
```json
{
  "token": "eyJhbGciOiJSUzI1NiJ9...",
  "access_token": "eyJhbGciOiJSUzI1NiJ9...",
  "expires_in": 300
}
```

**4. Using the Token**
- Extract the `token` field from the JSON response
- Add it to HTTP headers as: `Authorization: Bearer {token}`
- Include this header in all subsequent registry API calls

Implement the `get_auth_token` function that gets authentication tokens for Docker Hub.
"""

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
        if registry == 'registry-1.docker.io':
            # Get auth token for Docker Hub
            token_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{image}:pull"
            token_resp = requests.get(token_url)
            token_resp.raise_for_status()
            token = token_resp.json()['token']
            headers['Authorization'] = f'Bearer {token}'
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



"""
<details>
<summary>Hints</summary>
- Create empty headers = {}
- If registry == 'registry-1.docker.io':
  - Build URL: f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{image}:pull"
  - Get token: requests.get(token_url).json()['token']
  - Add header: headers['Authorization'] = f'Bearer {token}'
- Return headers
</details>
"""

# %%
"""
### Exercise 1.3: Manifest Discovery and Architecture Selection

Retrieve image manifests and select the appropriate architecture variant.

Docker images support multiple architectures. The manifest list contains manifests for 
different platforms (architecture + variant combinations). Your task is to:

1. Fetch the manifest list from the registry
2. Find the manifest for the target architecture
3. Return the digest of the selected manifest

<details>
<summary>Vocabulary: Docker Manifests and Architecture</summary>

- **Manifest**: JSON document describing image layers, configuration, and metadata
- **Manifest List**: Multi-architecture manifest containing platform-specific manifests
- **Digest**: SHA256 hash that uniquely identifies a manifest or layer
- **Platform**: Combination of architecture (amd64, arm64) and optional variant (v7, v8)
- **Architecture**: CPU architecture (amd64, arm64, arm, etc.)
- **Variant**: Sub-architecture version (e.g., armv7, armv8)

</details>

#### Exercise - implement get_target_manifest

> **Difficulty**: 🔴🔴🔴⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~20 minutes on this exercise.

**API Usage Instructions:**

Understanding Docker's multi-architecture support is crucial for modern containerization. Here's how to discover and select the right manifest:

**1. Building the Manifest List URL**

Docker registries use a standardized API format for accessing manifests:
- Format: `https://{registry}/v2/{image}/manifests/{tag}`
- Example: `https://registry-1.docker.io/v2/library/hello-world/manifests/latest`
- **What it does**: Fetches the manifest list containing all available architectures for an image

**2. Understanding Multi-Architecture Manifests**

Modern Docker images support multiple CPU architectures:
- **Manifest List**: Container for platform-specific manifests
- **Platform Object**: Contains `architecture` (e.g., "amd64", "arm64") and optional `variant` (e.g., "v8")
- **Architecture Matching**: Find the manifest that matches your target architecture

**3. Selecting the Right Architecture**

The manifest list contains an array of manifests, each with platform information:
```json
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
```

**4. Error Handling**

If the requested architecture isn't available:
- Collect all available architectures from the manifest list
- Raise a helpful ValueError with available options
- Include variant information when present

Implement the `get_target_manifest` function that selects the appropriate architecture manifest.
"""

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
    if "SOLUTION":
        # Get manifest list
        manifest_list_url = f"https://{registry}/v2/{image}/manifests/{tag}"
        print(f"Fetching manifest list from: {manifest_list_url}")

        resp = requests.get(manifest_list_url, headers=headers)
        resp.raise_for_status()
        manifest_list = resp.json()

        # Find the manifest for our target architecture
        target_manifest = None
        for manifest in manifest_list.get('manifests', []):
            platform = manifest.get('platform', {})
            if platform.get('architecture') == target_arch:
                # Check variant if specified
                if target_variant:
                    if platform.get('variant') == target_variant:
                        target_manifest = manifest
                        break
                else:
                    # No variant specified, take the first match
                    target_manifest = manifest
                    break

        if not target_manifest:
            available_archs = []
            for manifest in manifest_list.get('manifests', []):
                platform = manifest.get('platform', {})
                arch_str = platform.get('architecture', 'unknown')
                if platform.get('variant'):
                    arch_str += f" {platform.get('variant')}"
                available_archs.append(arch_str)

            raise ValueError(f"No manifest found for architecture {target_arch}"
                             f"{f' variant {target_variant}' if target_variant else ''}. "
                             f"Available: {', '.join(available_archs)}")

        manifest_digest = target_manifest['digest']
        print(f"Found manifest for {target_arch}: {manifest_digest}")
        return manifest_digest
    else:
        # TODO: Implement manifest discovery
        # 1. Build manifest list URL
        # 2. Make HTTP request with headers
        # 3. Parse JSON response
        # 4. Find manifest matching target_arch and target_variant
        # 5. Return the digest, or raise ValueError if not found
        return "sha256:placeholder"  # Placeholder return

"""
<details>
<summary>Hints</summary>
- Build the manifest list URL using the format: https://{registry}/v2/{image}/manifests/{tag}
- Use requests.get() with the provided headers to fetch the manifest list
- Parse the JSON response and look for the 'manifests' array
- Iterate through each manifest and check the 'platform' object
- Match target_arch with platform.architecture
- If target_variant is specified, also match it with platform.variant
- Return the 'digest' field from the matching manifest
- If no match is found, collect available architectures and raise ValueError with helpful message
</details>
"""


# %%
"""
### Exercise 1.4: Manifest Processing

Process the selected manifest to extract layer information and metadata.

Once you have the manifest digest, you need to fetch the actual manifest document and 
extract the layer information. The manifest contains metadata about each layer including 
digests and sizes.

<details>
<summary>Vocabulary: Manifest Structure</summary>

- **Manifest v2 Schema**: Docker's current manifest format specification
- **Layer**: A filesystem changeset stored as a compressed tar archive
- **Media Type**: MIME type indicating the format of manifest or layer data
- **Layer Digest**: SHA256 hash uniquely identifying a layer blob
- **Layer Size**: Compressed size of the layer in bytes

</details>

#### Exercise - implement get_manifest_layers

> **Difficulty**: 🔴🔴⚪⚪⚪  
> **Importance**: 🔵🔵🔵⚪⚪
> 
> You should spend up to ~15 minutes on this exercise.

**API Usage Instructions:**

Once you have the manifest digest, you need to fetch the actual manifest document to get layer information:

**1. Building the Manifest URL**
Use the manifest digest to fetch the specific manifest:
- Format: `https://{registry}/v2/{image}/manifests/{manifest_digest}`
- Example: `https://registry-1.docker.io/v2/library/hello-world/manifests/sha256:abc123...`
- **What it does**: Fetches the specific manifest document for an architecture

**2. Setting the Accept Header**

Docker registries require specific content type headers:
- Header: `Accept: application/vnd.docker.distribution.manifest.v2+json`
- **Why needed**: Tells the registry which manifest format version to return
- **Important**: Without this header, you might get an incompatible manifest format

**4. Manifest Document Structure**

The manifest contains metadata about all layers:
```json
{
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "layers": [
    {
      "digest": "sha256:layer1hash...",
      "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
      "size": 1234567
    },
    {
      "digest": "sha256:layer2hash...",
      "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", 
      "size": 2345678
    }
  ]
}
```

**5. Extracting Layer Information**
- Get the `layers` array from the manifest JSON
- Each layer object contains `digest` and `size` fields
- Return the layers list for downloading

Implement the `get_manifest_layers` function that fetches and processes the manifest.
"""

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
    if "SOLUTION":
        # Get the actual manifest using the digest
        manifest_url = f"https://{registry}/v2/{image}/manifests/{manifest_digest}"
        headers_copy = headers.copy()
        headers_copy['Accept'] = 'application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json'

        print(f"Fetching manifest from: {manifest_url}")
        resp = requests.get(manifest_url, headers=headers_copy)
        resp.raise_for_status()
        manifest = resp.json()

        print(f"Manifest type: {manifest.get('mediaType', 'unknown')}")
        layers = manifest.get('layers', [])
        print(f"Number of layers: {len(layers)}")

        return layers
    else:
        # TODO: Implement manifest processing
        # 1. Build manifest URL using digest
        # 2. Add Accept header for v2 manifest format
        # 3. Make HTTP request
        # 4. Parse JSON and extract layers
        # 5. Return list of layer dictionaries
        return []  # Placeholder return


# %%
"""
### Exercise 1.5: Layer Download and Extraction

Download and extract individual layers to reconstruct the container filesystem.

The final step is to download each layer blob and extract it to the output directory. 
Each layer is a gzipped tar archive that needs to be extracted in order.

<details>
<summary>Vocabulary: Layer Extraction</summary>

- **Blob**: Binary large object - the actual compressed layer data
- **Gzipped Tar**: Compressed archive format (.tar.gz) used for layer storage
- **Layer Extraction**: Unpacking layer contents to filesystem in order
- **Streaming Download**: Downloading large files without loading entirely into memory
- **Filesystem Layering**: Building final filesystem by applying layers sequentially

</details>

#### Exercise - implement download_and_extract_layers

> **Difficulty**: 🔴🔴🔴⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~20 minutes on this exercise.

Implement the `download_and_extract_layers` function that downloads and extracts all layers. Learn about [Docker image layers](https://docs.docker.com/storage/storagedriver/) and [tarfile processing in Python](https://docs.python.org/3/library/tarfile.html).

**API Usage Instructions:**

Think of Docker images like a layered cake! Each layer adds something new to the final image. Here's how to download and extract them:

**1. Building the Download URL** 

Think of this like creating an address to find a package online:
- Format: `https://{registry}/v2/{image}/blobs/{digest}`
- Example: `https://registry-1.docker.io/v2/library/hello-world/blobs/sha256:abc123...`
- **What it means**: Just like how you need a complete address to mail a letter, you need the full URL to download a Docker layer

**2. Unpacking the Compressed Files** 

Docker layers are like ZIP files that are also compressed (like a ZIP file inside another ZIP file):
- **What they are**: Gzipped tar archives (`.tar.gz` files)
- **How to open them**: 
  - `BytesIO(blob_resp.content)` - turns the downloaded data into a file-like object
  - `tarfile.open(fileobj=BytesIO(...), mode='r:gz')` - opens the compressed archive
  - `tar.extractall(output_dir)` - extracts all files to your folder

**3. Building the Final Image Layer by Layer** 

Like building with LEGO blocks, each layer adds something:
- **Layer 1**: Base operating system (like the foundation of a house)
- **Layer 2**: Application files (like adding rooms)
- **Layer 3**: Configuration files (like adding furniture)
- **Important**: Later layers can replace earlier ones (like updating a LEGO model)

**Real-world analogy**: Think of it like downloading and assembling a piece of furniture from IKEA - you get the parts (layers), unpack them, and build them in order!
"""

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
    if "SOLUTION":
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Download and extract layers in order
        for i, layer in enumerate(layers):
            digest = layer['digest']
            size = layer.get('size', 0)
            print(f"\nProcessing layer {i + 1}/{len(layers)}: {digest} ({size} bytes)")

            # Download layer blob
            blob_url = f"https://{registry}/v2/{image}/blobs/{digest}"
            blob_resp = requests.get(blob_url, headers=headers, stream=True)
            blob_resp.raise_for_status()

            # Extract layer (layers are gzipped tarballs)
            print(f"  Extracting to {output_dir}...")
            with tarfile.open(fileobj=BytesIO(blob_resp.content), mode='r:gz') as tar:
                tar.extractall(output_dir)

        print(f"\n✓ Extracted {len(layers)} layers to {output_dir}")
    else:
        # TODO: Implement layer download and extraction
        # 1. Create output directory
        # 2. For each layer:
        #    a. Build blob URL using digest
        #    b. Download blob with streaming
        #    c. Extract as gzipped tar to output_dir
        # 3. Print progress information
        pass

# %%
"""
### Exercise 1.6: Complete Implementation

Combine all the exercises into a complete `pull_layers` function that can extract any Docker image.

This function orchestrates all the previous functions to provide a complete Docker image extraction tool.

<details>
<summary>Vocabulary: Container Image Pipeline</summary>

- **Image Reference**: Complete specification of image including registry, name, and tag
- **Registry API**: RESTful HTTP API for accessing container images and metadata

</details>

#### Exercise - implement pull_layers

> **Difficulty**: 🔴🔴⚪⚪⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~10 minutes on this exercise.

Implement the complete `pull_layers` function using all the sub-functions you've created.
"""

def pull_layers(image_ref: str, output_dir: str, target_arch: str = TARGET_ARCH,
                target_variant: Optional[str] = TARGET_VARIANT) -> None:
    """
    Pull and extract Docker image layers for a specific architecture.

    Args:
        image_ref: Docker image reference (various formats supported)
        output_dir: Directory to extract layers to
        target_arch: Target architecture (default: auto-detected)
        target_variant: Target architecture variant (default: auto-detected)
    """
    if "SOLUTION":
        # Step 1: Parse image reference
        registry, image, tag = parse_image_reference(image_ref)

        print(f"Registry: {registry}")
        print(f"Image: {image}")
        print(f"Tag: {tag}")
        print(f"Target architecture: {target_arch}{f' variant {target_variant}' if target_variant else ''}")

        # Step 2: Get authentication
        headers = get_auth_token(registry, image)

        # Step 3: Get target manifest
        manifest_digest = get_target_manifest(registry, image, tag, headers, target_arch, target_variant)

        # Step 4: Get layers from manifest
        layers = get_manifest_layers(registry, image, manifest_digest, headers)

        # Step 5: Download and extract layers
        download_and_extract_layers(registry, image, layers, headers, output_dir)

        print(f"✓ Successfully extracted {image_ref} to {output_dir}")
        print(f"  Architecture: {target_arch}{f' variant {target_variant}' if target_variant else ''}")
    else:
        # TODO: Implement complete pull_layers function
        # Use all the functions you've implemented above:
        # 1. parse_image_reference()
        # 2. get_auth_token()
        # 3. get_target_manifest()
        # 4. get_manifest_layers()
        # 5. download_and_extract_layers()
        pass


test_pull_layers_complete(pull_layers)

# %%
# pull_layers("alpine:latest", "./extracted_alpine")
# pull_layers("python:3.12-alpine", "./extracted_python")
