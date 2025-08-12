#!/usr/bin/env python3

# %%
"""
# W2D2 - Containerization: Internals and Security

Today you'll learn the fundamentals of containerization by building your own container runtime from the ground up. You'll understand how modern container technologies like Docker work under the hood by implementing the core isolation mechanisms yourself using Linux primitives.

**IMPORTANT SECURITY NOTICE**: The techniques you'll learn today involve low-level system operations that can affect system stability. You must:
- Only practice on systems you own or have explicit permission to modify
- Be careful when working with system calls and kernel features
- Understand that improper use of these techniques can compromise system security

This lab will teach you the building blocks that power modern containerization platforms, giving you deep insight into both their capabilities and limitations.

<!-- toc -->

## Content & Learning Objectives

### 1️⃣ Docker Image Layer Extraction
Implement a custom image layer extraction tool by interacting directly with Docker registry APIs.

> **Learning Objectives**
> - Understand Docker image structure and layering
> - Implement registry authentication and manifest processing
> - Download and extract compressed layer archives

### 2️⃣ Container Isolation with Chroot
Create isolated filesystem environments using chroot, one of the fundamental isolation mechanisms.

> **Learning Objectives**  
> - Understand chroot filesystem isolation
> - Execute commands in isolated environments
> - Explore the foundation of container filesystem isolation

### 3️⃣ Resource Management with Cgroups  
Implement resource limits and management using Linux cgroups for memory and CPU control.

> **Learning Objectives**
> - Create and configure cgroups with resource limits
> - Assign processes to cgroups for resource management
> - Combine cgroup limits with chroot isolation

### 4️⃣ Network Isolation and Container Networking
Set up isolated network environments using namespaces, bridges, and virtual ethernet pairs.

> **Learning Objectives**
> - Understand container networking fundamentals
> - Implement network isolation with namespaces
> - Create bridge networks for container communication

### 5️⃣ Security Monitoring and Threat Detection
Implement security monitoring to detect container escape attempts and malicious syscalls.

> **Learning Objectives**
> - Monitor dangerous syscalls in real-time
> - Detect CVE-2024-0137 and similar container escape attempts
> - Implement automated threat response

### 6️⃣ Docker Commit
Implement the Docker commit functionality to save container changes as new image layers.

> **Learning Objectives**
> - Understand Docker image layering
> - Implement container state capture
> - Create new image layers from container modifications

## Setup
### If using devcontainers

```bash
sudp apt-get update
sudo apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        python3-full \
        btrfs-progs \
        iproute2 \
        iptables \
        strace \
        cgroup-tools \
        bash \
        curl \
        ca-certificates \
        dnsutils \
        docker.io \
        git \
        autoconf \
        automake \
        gettext \
        autopoint \
        libtool \
        iputils-ping

sudo chattr +i /etc/resolv.conf 2>/dev/null
```

<details>
<summary>Copy this into devcontainer.json and rebuild the container</summary>
```json
// For format details, see https://aka.ms/devcontainer.json. For config options, see the
// README at: https://github.com/devcontainers/templates/tree/main/src/python
{
	"name": "AI Security Bootcamp",
	// Or use a Dockerfile or Docker Compose file. More info: https://containers.dev/guide/dockerfile
	"image": "mcr.microsoft.com/devcontainers/python:1-3.12-bullseye",
	//
	// Features to add to the dev container. More info: https://containers.dev/features.
	"features": {
		// Enable Docker-outside-of-Docker to use the host's Docker daemon
		"ghcr.io/devcontainers/features/docker-outside-of-docker:1.6.3": {}
	},
	//
	// Runtime arguments to match your docker run command
	"runArgs": [
		"--network=host",
		"--privileged",
		"--cgroupns=host"
	],
	//
	// Use 'forwardPorts' to make a list of ports inside the container available locally.
	// "forwardPorts": [],
	//
	// Mount SSH keys into the container and Docker socket
	"mounts": [
		"source=${localWorkspaceFolder}/ssh,target=/mnt/ssh,type=bind",
		"source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind"
	],
	//
	// Use 'postCreateCommand' to run commands after the container is created.
	"postCreateCommand": "/bin/bash .devcontainer/setup-devcontainer.sh",
	//
	// Configure tool-specific properties.
	"customizations": {
		"vscode": {
			"extensions": [
				"ms-python.python",
				"ms-python.vscode-pylance",
				"ms-toolsai.jupyter",
				"charliermarsh.ruff",
				"bierner.markdown-mermaid"
			],
			"settings": {
				"editor.formatOnSave": true,
				"editor.codeActionsOnSave": {
					"source.fixAll": "explicit",
					"source.organizeImports": "never"
				},
				"ruff.lineLength": 120,
				"ruff.targetVersion": "py312",
				"[python]": {
					"editor.defaultFormatter": "charliermarsh.ruff"
				},
				"files.insertFinalNewline": true
			}
		}
	},
	//
	// Uncomment to connect as root instead. More info: https://aka.ms/dev-containers-non-root.
	"remoteUser": "root"
}
```
</details>

### If not using devcontainers
<details>
<summary>Installation Instructions</summary>
**Install Docker**: Ensure you have Docker installed on your system. Follow the [official Docker installation guide](https://docs.docker.com/get-docker/) for your platform. On linux, you can also install just the [docker engine](https://docs.docker.com/engine/install/ubuntu/) without the full Docker Desktop.

**Build and Run Container.** This setup creates a privileged container environment that allows you to experiment with low-level Linux containerization features like cgroups, namespaces, and network isolation. The exercises in this lab require direct access to system resources that are normally restricted in containers.

```bash
# Build Docker image from current directory
docker build --network=host . -t mydocker

# Run container with host networking and required privileges
# - --network host: Use host networking
# - --privileged: Run container with extended privileges
# - --cgroupns=host: Use host's cgroup namespace
# - -v /var/run/docker.sock:/var/run/docker.sock: Mount Docker socket from host
# - -it: Interactive terminal
# - --rm: Remove container after exit
docker run --rm --network host --privileged --cgroupns=host -it -v /var/run/docker.sock:/var/run/docker.sock mydocker /bin/bash
```

> [!TIP]
> If building the Docker image fails with a 400 Bad Request error response, just try building it again (this happens sometimes due to network issues)

Once inside the privileged container, run the exercises:

```bash
python3 w2d2_answers.py
```
</details>
⚠️ **WARNING**: This setup runs containers with elevated privileges that bypass normal security restrictions. This is necessary for learning container internals but should NEVER be used in production environments. 

## Cleanup Docker Environment

After COMPLETING the exercises, clean up to prevent resource conflicts.

⚠️ **WARNING**: This will remove all containers, networks, images and volumes. If you want to keep your environment/devcintainer, run `docker ps` and only kill the appropriate containers.

```bash
# Stop all running containers (including any test containers created during exercises)
docker stop $(docker ps -aq)

# Remove all containers (cleans up test containers from networking exercises)
docker rm $(docker ps -aq)

# Remove all unused containers, networks, images and volumes
# This cleans up extracted images from Exercise 1 and test networks from Exercise 5
docker system prune --all --volumes
```

## Understanding Containerization

Before diving into the technical implementation, let's understand what containerization provides and why it became so popular in modern software deployment.

### What Are Containers?

Containers are **lightweight, portable execution environments** that package applications with their dependencies while **sharing the host operating system kernel**. Unlike virtual machines that virtualize entire hardware stacks, containers use Linux kernel features to provide isolation at the process level.

Key characteristics of containers:
- **Process Isolation**: Each container runs in its own process space
- **Filesystem Isolation**: Containers have their own filesystem view
- **Resource Limits**: CPU, memory, and I/O can be controlled and limited
- **Network Isolation**: Containers can have isolated network stacks
- **Portability**: Containers run consistently across different environments

![Container vs Virtual Machine Architecture](https://www.criticalcase.com/wp-content/uploads/2021/02/SCHEMA-CONTAINER-VS-VM.png)

A key difference is that containers virtualize the operating system, packaging only the application and its dependencies but delegating system calls to the host kernel. Virtual machines, in contrast, virtualize the underlying physical hardware and each run a full guest operating system with its own kernel instance, which provides strong isolation but requires more resources and longer startup times. 

### Linux Kernel Features for Containerization

Modern containerization relies on several Linux kernel features:

<img src="./img/isolation.png" alt="Isolation features" height="300" /><br><sub>Source: [datadoghq.com](https://securitylabs.datadoghq.com/articles/container-security-fundamentals-part-2/)</sub>

1. **Namespaces**: Provide isolation of system resources ([Linux namespaces intro](https://blog.nginx.org/blog/what-are-namespaces-cgroups-how-do-they-work#:~:text=What%20Are%20Namespaces%3F), [namespace types](https://securitylabs.datadoghq.com/articles/container-security-fundamentals-part-2))
   - PID namespace: Process ID isolation
   - Mount namespace: Filesystem mount point isolation
   - Network namespace: Network stack isolation ([network namespaces tutorial](https://blog.scottlowe.org/2013/09/04/introducing-linux-network-namespaces/))
   - UTS namespace: Hostname and domain name isolation
   - User namespace: User and group ID isolation
   - IPC namespace: Inter-process communication isolation
   - Time: Time settings isolation
   - Cgroup namespace: cgroup isolation (see below) to prevent leaking information about other processes through cgroups

2. **Control Groups (cgroups)**: Resource limiting and accounting ([cgroups intro](https://blog.nginx.org/blog/what-are-namespaces-cgroups-how-do-they-work#:~:text=namespaces%20and%20cgroups.-,What%20Are%20cgroups%3F,-A%20control%20group), [Red Hat cgroups guide](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/resource_management_guide/ch01)) including
   - Memory limits and usage tracking
   - CPU time and priority control
   - I/O bandwidth limiting ([cgroups v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html))
   - Device access control

3. **Union Filesystems**: Layered filesystem management. One of these drivers is usually used:
   - OverlayFS: Efficient copy-on-write filesystem ([OverlayFS documentation](https://docs.kernel.org/filesystems/overlayfs.html))
   - AUFS: Another union filesystem (deprecated)
   - Device Mapper: Block-level storage driver

4. **Security Features**: Additional isolation and access control
   - Capabilities: Fine-grained privilege control ([Linux capabilities manual](https://man7.org/linux/man-pages/man7/capabilities.7.html))
   - SELinux/AppArmor: Mandatory access control
   - Seccomp: System call filtering ([seccomp tutorial](https://www.armosec.io/blog/seccomp-internals-part-1/))

### Container Image Format

Container images are **layered filesystems** packaged in a standardized format. Each layer represents a set of filesystem changes, and layers are stacked to create the final container filesystem.

**Image Layers Example**:
```
┌─────────────────────────────────────┐
│     Application Layer               │  ← Your app and configs
├─────────────────────────────────────┤
│     Runtime Dependencies            │  ← Python, Node.js, etc.
├─────────────────────────────────────┤
│     Package Manager Updates         │  ← apt update, yum update
├─────────────────────────────────────┤
│     Base OS Layer                   │  ← Ubuntu, Alpine, etc.
└─────────────────────────────────────┘
```

This layered approach provides several benefits:
- **Efficiency**: Common layers are shared between images ([Docker layer sharing](https://docs.docker.com/storage/storagedriver/))
- **Caching**: Unchanged layers don't need to be re-downloaded 
- **Version Control**: Similar to Git, each layer has a unique hash ([content addressable storage](https://blog.docker.com/2016/02/docker-1-10/))
- **Security**: Individual layers can be scanned for vulnerabilities ([container image scanning](https://docs.docker.com/docker-hub/vulnerability-scanning/))

"""

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
        if image_ref.startswith("http"):
            # Full URL provided
            parts = image_ref.replace("https://", "").replace("http://", "").split("/")
            registry = parts[0]
            if "/manifests/" in image_ref:
                # Extract image and tag from URL
                image_parts = "/".join(parts[2:]).split("/manifests/")
                image = image_parts[0]
                tag = image_parts[1]
            else:
                image = "/".join(parts[1:-1])
                tag = parts[-1] if ":" in parts[-1] else "latest"
        else:
            # Docker image format (e.g., "hello-world:latest" or "gcr.io/project/image:tag")
            if "/" in image_ref and image_ref.split("/")[0].count(".") > 0:
                # Custom registry (e.g., gcr.io/project/image)
                parts = image_ref.split("/", 1)
                registry = parts[0]
                image_and_tag = parts[1]
            else:
                # Docker Hub
                registry = "mirror.gcr.io"  # Default to Docker Hub mirror
                image_and_tag = image_ref
                if "/" not in image_and_tag:
                    image_and_tag = f"library/{image_and_tag}"

            if ":" in image_and_tag:
                image, tag = image_and_tag.rsplit(":", 1)
            else:
                image = image_and_tag
                tag = "latest"

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
    if "SOLUTION":
        # Get manifest list
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
    if "SOLUTION":
        # Get the actual manifest using the digest
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
    if "SOLUTION":
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Download and extract layers in order
        for i, layer in enumerate(layers):
            digest = layer["digest"]
            size = layer.get("size", 0)
            print(f"\nProcessing layer {i + 1}/{len(layers)}: {digest} ({size} bytes)")

            # Download layer blob
            blob_url = f"https://{registry}/v2/{image}/blobs/{digest}"
            blob_resp = requests.get(blob_url, headers=headers, stream=True)
            blob_resp.raise_for_status()

            # Extract layer (layers are gzipped tarballs)
            print(f"  Extracting to {output_dir}...")
            with tarfile.open(fileobj=BytesIO(blob_resp.content), mode="r:gz") as tar:
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


# %%
pull_layers("alpine:latest", "./extracted_alpine")
pull_layers("python:3.12-alpine", "./extracted_python")

# %%
"""
#$ Container Isolation: Chroot Environments

Implement chroot (change root) isolation, one of the fundamental isolation mechanisms used in containers.

Chroot creates a new filesystem root directory for processes, effectively "jailing" them within a specific 
directory tree. This creates an isolated environment where the process cannot access files outside 
the designated directory tree. Learn more about [chroot fundamentals](https://wiki.archlinux.org/title/Chroot) and the [chroot system call](https://man7.org/linux/man-pages/man2/chroot.2.html).

Understanding chroot is essential for grasping how containers work under the hood. Docker and other 
container runtimes use chroot (or more advanced variants) to isolate container filesystems from 
the host system. See [how Docker uses chroot](https://docs.docker.com/engine/security/rootless/) and [container security best practices](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html).

<details>
<summary>Vocabulary: Chroot and Filesystem Isolation</summary>

- **Chroot**: Unix system call that changes the apparent root directory for a process
- **Chroot Jail**: Isolated environment where processes can only access files within a directory tree
- **Root Directory**: The top-level directory (/) in a filesystem hierarchy
- **Subprocess**: A separate process spawned and managed by the main program

</details>

### Exercise 2.1: Chroot Environment Execution

> **Difficulty**: 🔴🔴⚪⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~20 minutes on this exercise.

Implement the `run_chroot` function that executes commands in a chrooted environment.

The chroot system call is fundamental to container isolation. It changes the root directory for 
a process, creating a "jail" where the process can only access files within the specified directory tree.

Your task is to implement a function that:
1. Takes a directory path and optional command
2. Executes the command within the chrooted environment
3. Handles different command formats (string vs list)
4. Provides proper error handling and timeouts
5. Returns the execution result
"""

import subprocess


def run_chroot(
    chroot_dir: str, command: Optional[Union[str, List[str]]] = None
) -> Optional[subprocess.CompletedProcess]:
    """
    Run a command in a chrooted environment.

    This function creates an isolated filesystem environment by changing the root directory
    for the executed command. The process will only be able to access files within the
    specified chroot directory.

    Args:
        chroot_dir: Directory to chroot into (must contain necessary binaries and libraries)
        command: Command to run (default: /bin/sh)
                - If string: executed as shell command
                - If list: executed directly
                - If None: defaults to interactive shell

    Returns:
        CompletedProcess object with execution results, or None if error/timeout
    """
    if "SOLUTION":
        if command is None:
            command = ["/bin/sh"]
        elif isinstance(command, str):
            command = ["/bin/sh", "-c", command]

        print(f"Running chroot {chroot_dir} with command: {' '.join(command)}")

        result = subprocess.run(["chroot", chroot_dir] + command, capture_output=True, text=True, timeout=30)
        print(f"Exit code: {result.returncode}")
        if result.stdout:
            print(f"stdout:\n{result.stdout}")
        if result.stderr:
            print(f"stderr:\n{result.stderr}")
        return result
    else:
        # TODO: Implement chroot command execution
        # 1. Handle different command formats (None, string, list)
        # 2. Build the chroot command: ['chroot', chroot_dir] + command
        # 3. Execute with subprocess.run() with timeout and output capture
        # 4. Print execution details and results
        # 5. Handle TimeoutExpired and other exceptions
        # 6. Return the result or None on error
        pass


# %%
"""
## Container Resource Management: Cgroups

Implement cgroups (control groups) for resource management and isolation in containers.

Cgroups are a Linux kernel feature that provides resource management and isolation for containers. 
They allow you to limit, account for, and isolate resource usage (CPU, memory, disk I/O, etc.) of 
groups of processes. Read about [cgroup concepts](https://docs.kernel.org/admin-guide/cgroup-v2.html) and [cgroup management](https://systemd.io/CGROUP_DELEGATION/).

Cgroups are essential for container technology, providing the foundation for resource limits and 
guarantees. Docker, Kubernetes, and other container orchestration systems rely heavily on cgroups 
to manage resources fairly and prevent resource starvation. See how [Docker uses cgroups](https://docs.docker.com/config/containers/resource_constraints/) and [Kubernetes resource management](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/).

<details>
<summary>Vocabulary: Cgroups and Resource Management</summary>

- **Cgroups**: Linux kernel feature for grouping and managing process resources
- **Control Groups**: Another name for cgroups - groups of processes under resource control
- **Resource Controller**: Kernel module that manages specific resource types (memory, CPU, etc.)
- **Cgroup Hierarchy**: Tree structure of nested cgroups in /sys/fs/cgroup filesystem
- **Memory Limit**: Maximum amount of memory a cgroup can use
- **OOM Killer**: Out-of-memory killer that terminates processes when limits are exceeded

</details>

### Exercise 3.1: Basic Cgroup Creation

> **Difficulty**: 🔴🔴⚪⚪⚪  
> **Importance**: 🔵🔵🔵⚪⚪
> 
> You should spend up to ~15 minutes on this exercise.

Implement the `create_cgroup` function that creates a basic cgroup with memory limits.

- Cgroups are organized in a hierarchy in the `/sys/fs/cgroup` filesystem
- To create a cgroup, you need to create directories and write to control files
- The `cgroup.subtree_control` file controls which controllers are enabled for child cgroups
- The `memory.max` file sets the memory limit for the cgroup
```
"""

import signal
import time


def create_cgroup(cgroup_name, memory_limit=None, cpu_limit=None):
    """
    Create a cgroup with specified limits

    Args:
        cgroup_name: Name of the cgroup (e.g., 'demo')
        memory_limit: Memory limit (e.g., '100M', '1000000')
        cpu_limit: CPU limit (stretch)

    Returns:
        Path to the created cgroup
    """
    if "SOLUTION":
        cgroup_path = f"/sys/fs/cgroup/{cgroup_name}"

        # Create cgroup directory
        os.makedirs(cgroup_path, exist_ok=True)
        print(f"Created cgroup directory: {cgroup_path}")

        # Enable controllers in parent cgroup
        with open("/sys/fs/cgroup/cgroup.subtree_control", "w") as f:
            f.write("+cpu +memory +pids")
        print("Enabled cgroup controllers")

        # Set memory limit if specified
        if memory_limit:
            memory_max_path = f"{cgroup_path}/memory.max"
            with open(memory_max_path, "w") as f:
                f.write(str(memory_limit))
            print(f"Set memory limit to {memory_limit}")
        return cgroup_path
    else:
        # TODO: Implement basic cgroup creation
        # 1. Create a new cgroup directory with path /sys/fs/cgroup/{cgroup_name} - you will write files in this directory to configure the cgroup
        # 2. Enable controllers (+cpu +memory +pids) in parent cgroup
        # 3. Set memory limit if specified - write the memory limit to {cgroup_path}/memory.max, which will tell the kernel how much memory the cgroup can use
        # 4. Return the cgroup path
        # 5. Handle errors and return None on failure
        pass


"""
<details>
<summary>Hints</summary>
1. Use `os.makedirs()` to create the cgroup directory at `/sys/fs/cgroup/{cgroup_name}`
2. Write "+cpu +memory +pids" to /sys/fs/cgroup/cgroup.subtree_control to enable these controllers
3. If memory_limit is specified, write str(memory_limit) to {cgroup_path}/memory.max
4. Return the cgroup path for further use
</details>
"""

# %%
"""
### Exercise 3.2: Process Assignment

> **Difficulty**: 🔴⚪⚪⚪⚪  
> **Importance**: 🔵🔵⚪⚪⚪
> 
> You should spend up to ~10 minutes on this exercise.


Assign processes to cgroups for resource management.

Once a cgroup is created, processes can be assigned to it by writing their PIDs to the 
`cgroup.procs` file. This allows the cgroup to manage resources for those processes.

**WARNING:** This approach has race conditions! 
The process may already be running and consuming resources before being added to the cgroup.
This can lead to:
- Memory limits not being enforced if the process allocates memory before being added
- Resource accounting inconsistencies
- Potential security issues if the process escapes before cgroup assignment

We'll implement a better approach in a subsequent exercise (see `run_in_cgroup_chroot()`) but you can ignore the race condition for this exercise.


Implement the `add_process_to_cgroup` function that assigns processes to cgroups.
"""


def add_process_to_cgroup(cgroup_name, pid=None):
    """
    Add a process to a cgroup

    Args:
        cgroup_name: Name of the cgroup
        pid: Process ID (default: current process)
    """
    if "SOLUTION":
        if pid is None:
            pid = os.getpid()

        cgroup_procs_path = f"/sys/fs/cgroup/{cgroup_name}/cgroup.procs"

        with open(cgroup_procs_path, "w") as f:
            f.write(str(pid))
        print(f"Added process {pid} to cgroup {cgroup_name}")
        return True
    else:
        # TODO: Implement process assignment to cgroup
        # 1. Use current process PID if none specified
        # 2. Write PID to cgroup.procs file
        # 3. Handle errors and return success status
        pass


# %%
"""
### Exercise 3.3: Combined Cgroup-Chroot Execution

> **Difficulty**: 🔴🔴🔴⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~20 minutes on this exercise.


Execute commands with both cgroup limits and chroot isolation.

This exercise combines cgroup resource limits with chroot filesystem isolation, creating 
a more complete container-like environment.


Implement the `run_in_cgroup_chroot` function that executes commands with both cgroup and chroot isolation.
"""


def run_in_cgroup_chroot(cgroup_name, chroot_dir, command=None, memory_limit="100M"):
    """
    Run a command in both a cgroup and chroot environment

    Args:
        cgroup_name: Name of the cgroup to create/use
        chroot_dir: Directory to chroot into
        command: Command to run
        memory_limit: Memory limit for the cgroup
    """
    if "SOLUTION":
        # Create cgroup
        create_cgroup(cgroup_name, memory_limit=memory_limit)

        if command is None:
            command = ["/bin/sh"]
        elif isinstance(command, str):
            command = ["/bin/sh", "-c", command]

        # Create a shell script that adds the process to cgroup then chroots
        script = f"""
        echo $$ > /sys/fs/cgroup/{cgroup_name}/cgroup.procs
        chroot {chroot_dir} {" ".join(command)}
        """

        # Run without capturing output so we see it in real-time
        result = subprocess.run(["sh", "-c", script], timeout=60)
        return result
    else:
        # TODO: Implement combined cgroup-chroot execution
        # 1. Create cgroup with memory limit
        # 2. Handle command format (None, string, list)
        # 3. Create shell script that:
        #    - Adds process to cgroup
        #    - Executes chroot with command
        # 4. Run with timeout and error handling
        pass


# %%
"""
### Exercise 3.4: Comprehensive Cgroup Setup - Part 1

> **Difficulty**: 🔴🔴🔴⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~20 minutes on this exercise.

This exercise implements core memory management features that form the foundation 
of effective container resource isolation. Part 1 focuses on the critical memory 
controls needed to make resource limits actually work in production.

Implement comprehensive memory management including swap control, which is essential
for memory limits to function properly in containerized environments.
"""


def create_cgroup_comprehensive_part1(cgroup_name, memory, cpu):
    """
    Create a cgroup with comprehensive settings - Part 1: Basic setup

    Args:
        cgroup_name: Name of the cgroup (e.g., 'demo')
        memory_limit: Memory limit (e.g., '100M', '1000000')
        cpu_limit: CPU limit (not implemented yet)
    """
    if "SOLUTION":
        cgroup_path = create_cgroup(cgroup_name, memory_limit=memory, cpu_limit=cpu)

        # Disable swap for this cgroup (CRITICAL for memory limits to work properly)
        try:
            swap_max_path = f"{cgroup_path}/memory.swap.max"
            with open(swap_max_path, "w") as f:
                f.write("0")
            print("✓ Disabled swap for cgroup (critical for memory limits)")
        except Exception as e:
            print(f"Warning: Could not disable swap: {e}")

        print("✓ Part 1 - Core memory management setup complete")
        return cgroup_path
    else:
        # TODO: Implement basic cgroup creation with swap disabling
        # 1. Call create_cgroup() with the correct parameters to create the cgroup
        # 2. Disable swap - search for "swap.max" in https://docs.kernel.org/admin-guide/cgroup-v2.html
        # 3. Return cgroup path or None if critical steps fail
        pass


# %%
"""
### Exercise 3.5: Comprehensive Cgroup Setup - Part 2 (Optional)

> **Difficulty**: 🔴🔴🔴🔴⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~25 minutes on this exercise.

This exercise builds on Part 1 by adding advanced Out-of-Memory (OOM) handling, 
process management, and monitoring capabilities needed for production-ready container isolation.

Implement advanced OOM group killing, process assignment, and comprehensive verification
that builds on the core memory management from Part 1.
"""


def create_cgroup_comprehensive(cgroup_name, memory_limit=None, cpu_limit=None):
    """
    Create a cgroup with comprehensive settings - Part 2: Advanced OOM and Process Management

    This builds on Part 1 by adding advanced Out-of-Memory handling, process assignment,
    and comprehensive monitoring capabilities for production-ready container isolation.

    Args:
        cgroup_name: Name of the cgroup (e.g., 'demo')
        memory_limit: Memory limit (e.g., '100M', '1000000')
        cpu_limit: CPU limit (not implemented yet)
    """
    if "SOLUTION":
        print(f"Setting up comprehensive cgroup Part 2: {cgroup_name}")

        # Start with Part 1 - Core Memory Management
        cgroup_path = create_cgroup_comprehensive_part1(cgroup_name, memory_limit, cpu_limit)
        if not cgroup_path:
            print("✗ Part 1 setup failed, cannot continue with Part 2")
            return None

        print("✓ Part 1 complete, continuing with Part 2 - Advanced OOM and Process Management")

        # Set OOM killer to be more aggressive for this cgroup
        oom_group_path = f"{cgroup_path}/memory.oom.group"
        with open(oom_group_path, "w") as f:
            f.write("1")
        print("✓ Enabled OOM group killing (kills entire process group on OOM)")

        # Add current process to cgroup and set up OOM score adjustment
        if add_process_to_cgroup(cgroup_name):
            print("✓ Added current process to cgroup")
        else:
            print("⚠ Warning: Could not add process to cgroup")

        # Set oom_score_adj to make this process more likely to be killed
        with open("/proc/self/oom_score_adj", "w") as f:
            f.write("1000")

        print("✓ Set OOM score adjustment to 1000 (highest priority for killing)")

        print("✓ Part 2 - Advanced OOM and process management complete")
        print(f"✓ Full comprehensive cgroup setup finished for: {cgroup_name}")
        return cgroup_path
    else:
        # TODO: Part 2 implementation
        # 1. Call create_cgroup_comprehensive_part1()
        # 2. Enable OOM group killing + assign process + set OOM score (see the documentation!)
        # 3. Return cgroup path
        pass


# test_create_cgroup_comprehensive(test_memory_comprehensive)
# %%
"""
### Summary: Understanding Cgroups

Through these exercises, you've learned about cgroups using the actual implementations from a real container system:

**Key Concepts:**

1. **Resource Isolation**: Cgroups provide fine-grained control over system resources
2. **Memory Management**: Advanced memory limits, swap control, and OOM handling
3. **Process Management**: Assigning processes to resource groups
4. **Container Foundation**: Cgroups + chroot + namespaces = containers

**Security Implications**

- **Resource Exhaustion**: Prevent DoS attacks through resource limits
- **Isolation**: Limit blast radius of compromised containers
"""


def run_in_cgroup_chroot_namespaced(cgroup_name, chroot_dir, command=None, memory_limit="100M"):
    """
    Run a command in cgroup, chroot, and namespace isolation

    Args:
        cgroup_name: Name of the cgroup to create/use
        chroot_dir: Directory to chroot into (must contain basic filesystem structure)
        command: Command to run (defaults to /bin/sh if None)
        memory_limit: Memory limit for the cgroup (e.g., "100M")

    Returns:
        Exit code of the command, or None if error occurred
    """
    # Create cgroup with memory limit
    create_cgroup(cgroup_name, memory_limit=memory_limit)

    # Prepare command - default to shell if none provided
    if command is None:
        command = ["/bin/sh"]
    elif isinstance(command, str):
        command = ["/bin/sh", "-c", command]

    print(f"Running `{command}` in cgroup {cgroup_name} with chroot {chroot_dir} and namespaces")
    # TODO: Implement namespace isolation following these steps:

    # Step 1: Fork a child process
    # (Creates a copy of our program - parent and child run separately)
    # Learn more: https://linuxhint.com/fork-system-call-linux/ and https://www.w3schools.com/python/ref_os_fork.asp
    # documentation: https://docs.python.org/3/library/os.html#os.fork

    def signal_handler(signum, frame):
        pass

    child_pid = os.fork()
    if child_pid == 0:
        signal.signal(signal.SIGUSR1, signal_handler)
        signal.pause()

        try:
            subprocess.run(
                [
                    "unshare",
                    "--pid",  # Process ID namespace isolation
                    "--mount",  # Mount namespace isolation
                    "--net",  # Network namespace isolation
                    "--uts",  # Hostname namespace isolation
                    "--ipc",  # IPC namespace isolation
                    "--fork",  # Fork after creating namespaces
                    "chroot",
                    chroot_dir,  # Change root directory
                ]
                + command,
                check=True,
            )
            os._exit(0)

        except Exception as e:
            print(e)
            os._exit(1)

    else:
        if add_process_to_cgroup(cgroup_name, child_pid):
            os.kill(child_pid, signal.SIGUSR1)
        else:
            os.kill(child_pid, signal.SIGTERM)

            # Step 7: Wait for child process to complete
        _, status = os.waitpid(child_pid, 0)
        exit_code = os.WEXITSTATUS(status)

        print(f"Exit code: {exit_code}")
        return exit_code

    # Step 2: In child process:
    #   - Set up signal handler for SIGUSR1 (like a doorbell to wake up the child)
    #     See: https://docs.python.org/3/library/signal.html
    #   - Wait for parent to finish setup and send a signal
    #   - After receiving signal, use unshare command to create isolated environments:
    #     See: https://man7.org/linux/man-pages/man1/unshare.1.html

    # Step 3: In parent process:
    #   - Add child PID to cgroup (to limit resources like memory/CPU)
    #   - Send SIGUSR1 signal to child (tells it "you're ready to start")
    #   - Wait for child to finish running
    #   - Get the exit code to report success/failure

    # Think about why we did .fork() and the complicated signalling, as opposed to just running the commands sequentially.


# %%
from w2d2_test import test_namespace_isolation

# test_namespace_isolation(run_in_cgroup_chroot_namespaced)
# %%

import uuid

"""
Create and configure bridge0 interface with IP address
"""


def create_bridge_interface():
    try:
        # Check if running as root
        if os.geteuid() != 0:
            print("⚠ Warning: Bridge interface creation requires root privileges")
            print("Critical failure - bridge interface creation requires root privileges")
            sys.exit(1)  # Exit the Python process on critical failure

        #   - Check if bridge0 already exists
        result = subprocess.run(["ip", "link", "show", "bridge0"], capture_output=True, text=True)

        #   - Remove existing bridge if present
        if result.returncode == 0:
            # check if bridge has the correct IP
            ip_check_result = subprocess.run(["ip", "addr", "show", "bridge0"], capture_output=True, text=True)

            if "10.0.0.1/24" in ip_check_result.stdout:
                return True
            else:
                # remove existing
                subprocess.run(["ip", "link", "del", "bridge0"], capture_output=True, text=True)

        # Create bridge0 interface
        subprocess.run(["ip", "link", "add", "bridge0", "type", "bridge"], check=True)

        # Configure bridge0 with IP 10.0.0.1/24
        subprocess.run(["ip", "addr", "add", "10.0.0.1/24", "dev", "bridge0"], check=True)

        #   - Bring bridge0 up
        subprocess.run(["ip", "link", "set", "bridge0", "up"], check=True)

        return True
    except Exception:
        return False


from w2d2_test import test_bridge_interface

# Run the test
test_bridge_interface(create_bridge_interface)


# %%


import threading

# Dangerous syscalls for CVE-2024-0137
DANGEROUS_SYSCALLS = {"setns", "unshare", "mount", "pivot_root", "chroot", "clone", "socket", "bind", "connect"}


def monitor_container_syscalls(container_command, alert_callback):
    """
    Monitor syscalls by running strace INSIDE the container namespace

    Args:
        container_command: List of command and arguments to run in container
        alert_callback: Function to call when dangerous syscalls are detected

    Returns:
        Exit code of the monitored process
    """

    try:
        # TODO: Implement syscall monitoring
        # Create strace command with dangerous syscalls filter
        strace_cmd = [
            "strace",
            "-f",
            "-e",
            "trace=" + ",".join(DANGEROUS_SYSCALLS),
            "-o",
            "/dev/stderr",
        ] + container_command

        print(f"🔍 Running strace inside container: {' '.join(strace_cmd)}")

        process = subprocess.Popen(strace_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

        # Monitor stderr for syscall traces
        def monitor_stderr():
            if process.stderr:
                for line in iter(process.stderr.readline, ""):
                    if line.strip():
                        # Check for dangerous syscalls
                        if any(syscall in line for syscall in DANGEROUS_SYSCALLS):
                            alert_callback(line.strip(), process.pid)
                        # Also print container output
                        if not any(syscall in line for syscall in DANGEROUS_SYSCALLS):
                            print(f"[CONTAINER] {line.strip()}")

        # Monitor stdout for normal output
        def monitor_stdout():
            if process.stdout:
                for line in iter(process.stdout.readline, ""):
                    if line.strip():
                        print(f"[CONTAINER] {line.strip()}")

        # Start monitoring threads
        stderr_thread = threading.Thread(target=monitor_stderr, daemon=True)
        stdout_thread = threading.Thread(target=monitor_stdout, daemon=True)

        stderr_thread.start()
        stdout_thread.start()

        # Wait for process completion
        exit_code = process.wait()
        return exit_code

    except Exception as e:
        print(f"⚠ Container monitoring error: {e}")
        return -1


from w2d2_test import test_syscall_monitoring

# Run the test
test_syscall_monitoring(monitor_container_syscalls)
# %%
