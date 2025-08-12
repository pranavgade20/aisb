# Allow imports from parent directory
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

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



def test_commit():
    """Test commit functionality using wget installation pattern"""
    print("="*80)
    print("Testing docker commit...")
    
    # Setup Docker environment first

    setup_returncode = setup_docker_environment()
    if setup_returncode != 0:
        print("FAIL: Environment setup failed")
        print("Critical failure - Docker environment setup failed")
        sys.exit(1)  # Exit the Python process on critical failure
    print("Environment setup completed successfully!")
    print("-" * 40)
    
    # Test argument validation first
    returncode = commit([])
    if returncode != 1:  # Should fail with usage message
        print(f"FAIL: Commit should fail with no arguments")
        print("Critical failure - commit argument validation failed")
        sys.exit(1)  # Exit the Python process on critical failure
    
    # Test with single argument
    returncode = commit(['container_id'])
    if returncode != 1:  # Should fail with usage message
        print(f"FAIL: Commit should fail with single argument")
        print("Critical failure - commit single argument validation failed")
        sys.exit(1)  # Exit the Python process on critical failure
    
    # Test with invalid container
    returncode = commit(['nonexistent_container', 'nonexistent_image'])
    if returncode == 0:
        print("FAIL: Commit should fail with nonexistent container")
        print("Critical failure - commit should fail with nonexistent container")
        sys.exit(1)  # Exit the Python process on critical failure
    
    # Create test image for commit testing
    base_image_dir = os.path.expanduser('~/base-image')
    if not os.path.exists(base_image_dir):
        print("SKIP: No base image directory available for commit testing")
        return True
    
    # Initialize a new image from base and get the exact image ID
    img_id, returncode = init([base_image_dir])
    if returncode != 0 or not img_id:
        print("FAIL: Could not create test image for commit")
        print("Critical failure - exiting Python process")
        sys.exit(1)  # Exit the Python process on critical failure
    
    print(f"Using created image: {img_id}")
    time.sleep(1)
    
    # Test 1: Run wget command (should fail since wget is not installed)
    print("Step 1: Testing wget command (should fail)...")
    returncode = run([img_id, 'wget'])
    time.sleep(2)
    
    # Get container ID for wget test
    containers = _list_containers()
    wget_test_container = None
    for container in containers:
        if 'wget' in container['command'] and 'yum' not in container['command']:
            wget_test_container = container['id']
            break
    
    if wget_test_container:
        print(f"Wget test container: {wget_test_container}")
        # Check logs to confirm wget is not installed
        btrfs_path = get_btrfs_path()
        log_file = Path(btrfs_path) / wget_test_container / f"{wget_test_container}.log"
        if log_file.exists():
            try:
                with open(log_file, 'r') as f:
                    log_content = f.read()
                if 'command not found' in log_content or 'wget: command not found' in log_content:
                    print("Confirmed: wget command not found (as expected)")
                else:
                    print(f"Warning: Unexpected wget output: {log_content}")
            except Exception as e:
                print(f"Warning: Could not read wget test logs: {e}")
                sys.exit(1) 
        
        # Clean up test container
        rm([wget_test_container])
    
    # Test 2: Install wget using yum
    print("Step 2: Installing wget using yum...")
    returncode = run([img_id, 'yum', 'install', '-y', 'wget'])
    time.sleep(5)  # Give more time for yum install
    
    # Get container ID for yum install
    containers = _list_containers()
    yum_container = None
    for container in containers:
        if 'yum install -y wget' in container['command']:
            yum_container = container['id']
            break
    
    if not yum_container:
        print("FAIL: Could not find yum install container")
        print("Critical failure - exiting Python process")
        sys.exit(1)  # Exit the Python process on critical failure
    
    print(f"Yum install container: {yum_container}")
    
    # Test 3: Commit the changes
    print("Step 3: Committing changes to image...")
    commit_returncode = commit([yum_container, img_id])
    if commit_returncode != 0:
        print(f"FAIL: Commit failed with return code {commit_returncode}")
        print("Critical commit failure - exiting Python process")
        sys.exit(1)  # Exit the Python process on critical failure
    
    print(f"Successfully committed changes to image {img_id}")
    
    # Test 4: Verify wget now works by making HTTP request
    print("Step 4: Testing wget with HTTP request...")
    returncode = run([img_id, 'wget', '-qO-', 'http://httpbin.org/get'])
    time.sleep(3)
    
    # Get container ID for wget HTTP request
    containers = _list_containers()
    wget_http_container = None
    for container in containers:
        if 'wget -qO- http://httpbin.org/get' in container['command']:
            wget_http_container = container['id']
            break
    
    if wget_http_container:
        print(f"Wget HTTP request container: {wget_http_container}")
        
        # Check logs to verify HTTP request succeeded
        btrfs_path = get_btrfs_path()
        log_file = Path(btrfs_path) / wget_http_container / f"{wget_http_container}.log"
        if log_file.exists():

            with open(log_file, 'r') as f:
                log_content = f.read()
            
            print("Logs from wget HTTP request:")
            print(log_content[:200] + "..." if len(log_content) > 200 else log_content)
            
            if 'http://httpbin.org/get' in log_content or '"url"' in log_content:
                print("SUCCESS: wget successfully fetched data from httpbin.org")
            else:
                print("Warning: wget HTTP request may have failed or returned unexpected data")
        
        # Clean up HTTP test container
        rm([wget_http_container])
    else:
        print("Warning: Could not find wget HTTP request container")
    return True
