
## Docker Commit

In this exercise, you'll implement the Docker commit functionality to save container changes as new image layers. This is essential for creating persistent images from running containers. Learn about [Docker commit operations](https://docs.docker.com/reference/cli/docker/container/commit/) and [image layer management](https://docs.docker.com/storage/storagedriver/).

**Introduction**

Docker's layered filesystem architecture is one of its most powerful features, enabling efficient image storage and sharing. Each Docker image consists of multiple read-only layers stacked on top of each other, with each layer representing a set of filesystem changes.

**Understanding Docker Layers**

When you create a Docker image, each instruction in the Dockerfile creates a new layer:
- **Base Layer**: Contains the operating system files
- **Package Installation Layer**: Captures changes from `apt-get install` or `yum install`
- **Application Layer**: Contains your application code and dependencies
- **Configuration Layer**: Includes environment variables, exposed ports, etc.

**The Commit Process**

The `docker commit` command is crucial for creating new image layers from running containers. Here's how it works:

1. **Container State Capture**: When you commit a container, Docker creates a snapshot of all changes made to the container's writable layer
2. **Layer Creation**: These changes become a new read-only layer in the image
3. **Metadata Preservation**: Container configuration, environment variables, and other metadata are preserved
4. **Image Tagging**: The new layer is associated with a specific image name/tag

**Benefits of Layering**

- **Storage Efficiency**: Multiple images can share the same base layers
- **Fast Deployment**: Only changed layers need to be transferred
- **Version Control**: Each commit creates a new version of your image
- **Rollback Capability**: You can easily revert to previous image versions

**Real-World Use Cases**

- **Development Workflows**: Commit experimental changes to test new features
- **Debugging**: Save container state for analysis after issues occur
- **CI/CD Pipelines**: Create intermediate images during build processes
- **Data Science**: Save containers with installed packages and datasets

The commit functionality you'll implement will enable these powerful Docker workflows by capturing container state and creating new image layers efficiently.


```python


import glob
import random
from pathlib import Path
import requests
import tarfile
import json
import sys
import os
import platform
from io import BytesIO
from typing import Optional, List, Union, Tuple, Dict, Any
import subprocess
import signal
import time
import uuid
import threading

def get_btrfs_path():
    """Get btrfs path from environment or default"""
    return os.environ.get('DOCKER_DEMO_BTRFS_PATH', '/var/docker_demo')

def _run_bash_command(bash_script, show_realtime=False):
    """Execute bash commands using bash -c"""
    try:
        if show_realtime:
            process = subprocess.Popen(
                ['bash', '-c', bash_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            if process.stdout is not None:
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        print(output.rstrip())
            return_code = process.poll()
            return return_code if return_code is not None else 0
        else:
            result = subprocess.run(['bash', '-c', bash_script], capture_output=True, text=True)
            if result.returncode != 0:
                if result.stderr:
                    print(result.stderr, file=sys.stderr)
                return result.returncode
            if result.stdout:
                print(result.stdout.rstrip())
            return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

def _docker_check(container_id):
    """Check if container/image exists using Python subprocess"""
    btrfs_path = get_btrfs_path()
    try:
        result = subprocess.run(
            ['btrfs', 'subvolume', 'list', btrfs_path],
            capture_output=True, text=True, check=True
        )
        return container_id in result.stdout
    except subprocess.CalledProcessError:
        return False

def _generate_uuid(prefix="ps_"):
    """Generate UUID using Python instead of bash shuf"""
    return f"{prefix}{random.randint(42002, 42254)}"

def _directory_exists(directory):
    """Check if directory exists using Python"""
    return Path(directory).exists()

def _list_images():
    """List images using Python glob instead of bash for loop"""
    btrfs_path = get_btrfs_path()
    images = []
    for img_path in glob.glob(f"{btrfs_path}/img_*"):
        img_id = os.path.basename(img_path)
        source_file = os.path.join(img_path, 'img.source')
        if os.path.exists(source_file):
            with open(source_file, 'r') as f:
                source = f.read().strip()
            images.append({'id': img_id, 'source': source})
    return images

def _list_containers():
    """List containers using Python glob instead of bash for loop"""
    btrfs_path = get_btrfs_path()
    containers = []
    for ps_path in glob.glob(f"{btrfs_path}/ps_*"):
        ps_id = os.path.basename(ps_path)
        cmd_file = os.path.join(ps_path, f'{ps_id}.cmd')
        if os.path.exists(cmd_file):
            with open(cmd_file, 'r') as f:
                command = f.read().strip()
            containers.append({'id': ps_id, 'command': command})
    return containers

def _format_table_output(headers, rows):
    """Format table output using Python instead of bash echo -e"""
    if not rows:
        return '\t\t'.join(headers)
    output = ['\t\t'.join(headers)]
    for row in rows:
        output.append('\t\t'.join(row))
    return '\n'.join(output)

def help_command():
    """Display help message"""
    help_text = """DOCKER - Simplified version to demonstrate commit functionality

Usage: python3 <filename> [command] [args...]

Commands:
  init     Create an image from a directory
  images   List images
  ps       List containers
  run      Create a container
  commit   Commit a container to an image
  rm       Delete an image or container
  help     Display this message
"""
    print(help_text)
    return 0

def init(args):
    """Create an image from a directory and return the image ID: DOCKER init <directory>"""
    if len(args) < 1:
        return None, 1

    directory = args[0]
    if not _directory_exists(directory):
        print(f"No directory named '{directory}' exists", file=sys.stderr)
        return None, 1

    uuid = _generate_uuid("img_")
    if _docker_check(uuid):
        return init(args)

    btrfs_path = get_btrfs_path()
    bash_script = f"""
    set -o errexit -o nounset -o pipefail
    btrfs subvolume create "{btrfs_path}/{uuid}" > /dev/null
    cp -rf --reflink=auto "{directory}"/* "{btrfs_path}/{uuid}" > /dev/null
    [[ ! -f "{btrfs_path}/{uuid}"/img.source ]] && echo "{directory}" > "{btrfs_path}/{uuid}"/img.source
    echo "Created: {uuid}"
    """
    returncode = _run_bash_command(bash_script)
    if returncode == 0:
        return uuid, 0
    else:
        return None, returncode

def images(args):
    """List images: DOCKER images"""
    images_list = _list_images()
    if not images_list:
        print("IMAGE_ID\t\tSOURCE")
        return 0
    rows = [[img['id'], img['source']] for img in images_list]
    output = _format_table_output(['IMAGE_ID', 'SOURCE'], rows)
    print(output)
    return 0

def rm(args):
    """Delete an image or container: DOCKER rm <id>"""
    if len(args) < 1:
        print("Usage: python3 <filename> rm <id>", file=sys.stderr)
        return 1

    container_id = args[0]
    if not _docker_check(container_id):
        print(f"No container named '{container_id}' exists", file=sys.stderr)
        return 1

    btrfs_path = get_btrfs_path()
    bash_script = f"""
    set -o errexit -o nounset -o pipefail
    btrfs subvolume delete "{btrfs_path}/{container_id}" > /dev/null
    echo "Removed: {container_id}"
    """
    return _run_bash_command(bash_script)

def ps(args):
    """List containers: DOCKER ps"""
    containers = _list_containers()
    if not containers:
        print("CONTAINER_ID\t\tCOMMAND")
        return 0
    rows = [[container['id'], container['command']] for container in containers]
    output = _format_table_output(['CONTAINER_ID', 'COMMAND'], rows)
    print(output)
    return 0

def run(args):
    """Create a container: DOCKER run <image_id> <command>"""
    if len(args) < 2:
        print("Usage: python3 <filename> run <image_id> <command>", file=sys.stderr)
        return 1

    image_id = args[0]
    command = ' '.join(args[1:])

    if not _docker_check(image_id):
        print(f"No image named '{image_id}' exists", file=sys.stderr)
        return 1

    if not command.strip():
        print("Error: Command cannot be empty", file=sys.stderr)
        return 1

    uuid = _generate_uuid("ps_")
    if _docker_check(uuid):
        return run(args)

    btrfs_path = get_btrfs_path()
    bash_script = f"""
    set -o errexit -o nounset -o pipefail; shopt -s nullglob
    
    btrfs subvolume snapshot "{btrfs_path}/{image_id}" "{btrfs_path}/{uuid}" > /dev/null
    echo "{command}" > "{btrfs_path}/{uuid}/{uuid}.cmd"
    cp /etc/resolv.conf "{btrfs_path}/{uuid}"/etc/resolv.conf

    unshare -fmuip --mount-proc \\
    chroot "{btrfs_path}/{uuid}" \\
    /bin/sh -c "/bin/mount -t proc proc /proc && {command}" \\
    2>&1 | tee "{btrfs_path}/{uuid}/{uuid}.log" || true
    """
    return _run_bash_command(bash_script, show_realtime=True)
```

### Exercise 7.1: Implement commit functionality

In this exercise, you will implement the Docker commit functionality that allows you to save the current state of a running container as a new image. This is a fundamental Docker operation that enables:

1. **Container State Capture**: Save all filesystem changes made in a container
2. **Layer Creation**: Create new image layers from container modifications
3. **Metadata Preservation**: Maintain container configuration and environment settings
4. **Image Tagging**: Associate commits with specific image names/tags

You'll need to:
- Check if the container exists before committing
- Create a snapshot of the container's current state
- Handle cases where the target image already exists
- Preserve container metadata and configuration
- Return appropriate error codes and messages

#### Setup
Please run this exercise on an ubuntu 24.04 architecture machine and perform the same setup instructions as mentioned in the beginning of the file on the machine!


The commit process essentially creates a new image layer that captures all changes made to the container since it was created from its base image.

> **Difficulty**: 🔴🔴🔴⚪⚪
> **Importance**: 🔵🔵🔵🔵⚪
>
> You should spend up to ~15 minutes on this exercise.

Implement the complete commit functionality that captures container state, creates new image layers, and preserves metadata.


```python

def setup_docker_environment():
    """Setup Docker environment by running the required bash commands"""
    print("Setting up Docker environment...")
    
    setup_script = """
fallocate -l 10G ~/btrfs.img
mkdir -p /var/docker_demo
mkfs.btrfs ~/btrfs.img
mount -o loop ~/btrfs.img /var/docker_demo

# Create base image manually
docker pull almalinux:9
docker create --name temp almalinux:9
mkdir -p ~/base-image
docker export temp | tar -xC ~/base-image
docker rm temp
"""
    
    print("Running setup commands...")
    return _run_bash_command(setup_script, show_realtime=True)

def commit(args):
    """Commit a container to an image: DOCKER commit <container_id> <image_id>"""
    if len(args) < 2:
        print("Usage: python3 <filename> commit <container_id> <image_id>", file=sys.stderr)
        return 1

    container_id, image_id = args[0], args[1]
    
    if not _docker_check(container_id):
        print(f"No container named '{container_id}' exists", file=sys.stderr)
        return 1

    if not _docker_check(image_id):
        print(f"No image named '{image_id}' exists", file=sys.stderr)
        return 1

    btrfs_path = get_btrfs_path()
    # TODO: Implement commit functionality
    # Read https://btrfs.readthedocs.io/en/latest/Subvolumes.html
    # Delete existing image if it exists
    # Create snapshot of container as new image (look into btrfs subvolume snapshot)
    # Preserve container metadata and configuration
    bash_script = f"""
        set -o errexit -o nounset -o pipefail
        echo "TODO: Implement commit functionality"
        """
    return _run_bash_command(bash_script)
```

<details>
<summary>Hints</summary><blockquote>

- Delete existing image subvolume: btrfs subvolume delete "{btrfs_path}/{image_id}"
- Create snapshot from container: btrfs subvolume snapshot "{btrfs_path}/{container_id}" "{btrfs_path}/{image_id}"
</blockquote></details>


```python
from w2d2_commit_test import test_commit

test_commit()
```