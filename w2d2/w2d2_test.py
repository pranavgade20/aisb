# Allow imports from parent directory
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import requests
import tarfile
import json
import sys
import os
import platform
from io import BytesIO
from typing import Optional, List, Union, Tuple, Dict, Any
import subprocess
import shutil
import shutil
import subprocess
import signal
import time
import uuid
import threading
import glob
import random
from pathlib import Path


def test_parse_image_reference(parse_image_reference):
    """Test the image reference parsing function."""
    print("Testing image reference parsing...")
    
    # Test 1: Docker Hub shorthand
    registry, image, tag = parse_image_reference("hello-world:latest")
    assert registry == "mirror.gcr.io", f"Expected registry-1.docker.io, got {registry}"
    assert image == "library/hello-world", f"Expected library/hello-world, got {image}"
    assert tag == "latest", f"Expected latest, got {tag}"
    print("✓ Docker Hub shorthand parsing works")
    
    # Test 2: Custom registry
    registry, image, tag = parse_image_reference("gcr.io/google-containers/pause:3.2")
    assert registry == "gcr.io", f"Expected gcr.io, got {registry}"
    assert image == "google-containers/pause", f"Expected google-containers/pause, got {image}"
    assert tag == "3.2", f"Expected 3.2, got {tag}"
    print("✓ Custom registry parsing works")
    
    # Test 3: No tag specified (should default to latest)
    registry, image, tag = parse_image_reference("alpine")
    assert registry == "mirror.gcr.io", f"Expected registry-1.docker.io, got {registry}"
    assert image == "library/alpine", f"Expected library/alpine, got {image}"
    assert tag == "latest", f"Expected latest, got {tag}"
    print("✓ Default tag handling works")
    
    print("✓ Image reference parsing tests passed!\n" + "=" * 60)




def test_get_auth_token(get_auth_token):
    """Test the authentication token retrieval."""
    print("Testing authentication token retrieval...")
    
    # Test 1: Docker Hub authentication
    headers = get_auth_token("registry-1.docker.io", "library/hello-world")
    assert "Authorization" in headers, "Authorization header missing"
    assert headers["Authorization"].startswith("Bearer "), "Token should be Bearer type"
    print("✓ Docker Hub token retrieval works")
    
    # Test 2: Other registries (should return empty headers)
    headers = get_auth_token("gcr.io", "google-containers/pause")
    assert isinstance(headers, dict), "Should return dictionary"
    print("✓ Other registry handling works")
    
    print("✓ Authentication tests passed!\n" + "=" * 60)



def test_get_target_manifest(get_target_manifest, get_auth_token):
    """Test the manifest discovery function."""
    print("Testing manifest discovery...")
    
    # Test with a known multi-arch image
    registry = "mirror.gcr.io"
    image = "library/hello-world"
    tag = "latest"
    headers = get_auth_token(registry, image)
    
    # Test 1: Find amd64 manifest
    digest = get_target_manifest(registry, image, tag, headers, "amd64")
    assert digest.startswith("sha256:"), f"Digest should start with sha256:, got {digest}"
    print("✓ AMD64 manifest discovery works")
    
    # Test 2: Find arm64 manifest
    digest = get_target_manifest(registry, image, tag, headers, "arm64", "v8")
    assert digest.startswith("sha256:"), f"Digest should start with sha256:, got {digest}"
    print("✓ ARM64 manifest discovery works")
    
    # Test 3: Invalid architecture should raise ValueError
    try:
        get_target_manifest(registry, image, tag, headers, "invalid-arch")
        assert False, "Should have raised ValueError for invalid architecture"
    except ValueError:
        print("✓ Invalid architecture handling works")
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)
    
    print("✓ Manifest discovery tests passed!\n" + "=" * 60)



def test_get_manifest_layers(get_manifest_layers, get_auth_token, get_target_manifest):
    """Test the manifest processing function."""
    print("Testing manifest processing...")
    
    # Use a known image
    registry = "mirror.gcr.io"
    image = "library/hello-world"
    tag = "latest"
    headers = get_auth_token(registry, image)
    
    
    # Get manifest digest
    manifest_digest = get_target_manifest(registry, image, tag, headers, "amd64")
    
    # Get layers
    layers = get_manifest_layers(registry, image, manifest_digest, headers)
    
    assert isinstance(layers, list), "Layers should be a list"
    assert len(layers) > 0, "Should have at least one layer"
    
    # Check layer structure
    for layer in layers:
        assert 'digest' in layer, "Layer should have digest"
        assert 'size' in layer, "Layer should have size"
        assert layer['digest'].startswith('sha256:'), "Digest should start with sha256:"
        assert isinstance(layer['size'], int), "Size should be integer"
    
    print(f"✓ Found {len(layers)} layers")
    print("✓ Manifest processing works")
        
    
    print("✓ Manifest processing tests passed!\n" + "=" * 60)



def test_download_and_extract_layers(download_and_extract_layers, get_auth_token, 
                                   get_target_manifest, get_manifest_layers):
    """Test the layer download and extraction function."""
    print("Testing layer download and extraction...")
    
    # Use a small image for testing
    registry = "mirror.gcr.io"
    image = "library/hello-world"
    tag = "latest"
    output_dir = "./test_extracted"
    
    # Get authentication
    headers = get_auth_token(registry, image)
    
    # Get manifest
    manifest_digest = get_target_manifest(registry, image, tag, headers, TARGET_ARCH, TARGET_VARIANT)
    
    # Get layers
    layers = get_manifest_layers(registry, image, manifest_digest, headers)
    
    # Download and extract
    download_and_extract_layers(registry, image, layers, headers, output_dir)
    
    # Verify extraction
    assert os.path.exists(output_dir), "Output directory should exist"
    extracted_files = os.listdir(output_dir)
    assert len(extracted_files) > 0, "Should have extracted some files"
    
    print(f"✓ Successfully extracted to {output_dir}")
    print(f"✓ Found {len(extracted_files)} items in output directory")
    
    # Cleanup
    import shutil
    shutil.rmtree(output_dir, ignore_errors=True)
        
    
    print("✓ Layer download and extraction tests passed!\n" + "=" * 60)



def test_pull_layers_complete(pull_layers):
    """Test the complete pull_layers function."""
    print("Testing complete pull_layers function...")
    
    # Test with a small image
    test_cases = [
        ("hello-world:latest", "./extracted_hello_world"),
        ("alpine:latest", "./extracted_alpine"),
        ("python:3.12-alpine", "./extracted_python"),
    ]
    
    for image_ref, output_dir in test_cases:
        print(f"\nTesting {image_ref}...")
        pull_layers(image_ref, output_dir)
        
        # Verify extraction
        assert os.path.exists(output_dir), f"Output directory {output_dir} should exist"
        extracted_files = os.listdir(output_dir)
        assert len(extracted_files) > 0, f"Should have extracted files to {output_dir}"
        
        print(f"✓ Successfully extracted {image_ref}")
        
        # Cleanup
        import shutil
        shutil.rmtree(output_dir, ignore_errors=True)
            
    print("✓ Complete pull_layers tests passed!\n" + "=" * 60)



def test_run_chroot(run_chroot):
    """Test the chroot command execution function."""
    print("Testing chroot command execution...")
    
    # Test 1: Basic command execution in Alpine Linux environment
    print("\n1. Testing basic command execution:")
    result = run_chroot("./extracted_alpine", "echo 'Hello from chroot!'")
    if result:
        assert result.returncode == 0, "Echo command should succeed"
        assert "Hello from chroot!" in result.stdout, "Output should contain expected text"
        print("✓ Basic command execution works")
    else:
        print("⚠ Basic command test failed - may need Alpine environment")
    
    # Test 2: Testing with Python environment
    print("\n2. Testing Python version check:")
    result = run_chroot("./extracted_python", "python --version")
    if result:
        assert result.returncode == 0, "Python version command should succeed"
        assert "Python" in result.stdout or "Python" in result.stderr, "Should show Python version"
        print("✓ Python environment test works")
    else:
        print("⚠ Python test failed - may need Python environment")
    
    # Test 3: Testing file system isolation
    print("\n3. Testing filesystem isolation:")
    result = run_chroot("./extracted_alpine", "ls /")
    if result:
        assert result.returncode == 0, "Directory listing should succeed"
        # Should not see host filesystem
        assert "Users" not in result.stdout, "Should not see host directories"
        print("✓ Filesystem isolation verified")
    else:
        print("⚠ Filesystem isolation test failed")
    
    # Test 4: Testing command list format
    print("\n4. Testing command list format:")
    result = run_chroot("./extracted_alpine", ["echo", "List command works"])
    if result:
        assert result.returncode == 0, "List command should succeed"
        assert "List command works" in result.stdout, "Output should contain expected text"
        print("✓ Command list format works")
    else:
        print("⚠ Command list test failed")
    
    # Test 5: Testing error handling
    print("\n5. Testing error handling:")
    result = run_chroot("./extracted_alpine", "nonexistent_command")
    if result:
        assert result.returncode != 0, "Non-existent command should fail"
        print("✓ Error handling works")
    else:
        print("⚠ Error handling test failed")
    
    print("\n✓ Chroot tests completed!\n" + "=" * 60)



def test_create_cgroup(create_cgroup):
    """Test the basic cgroup creation function."""
    print("Testing basic cgroup creation...")
    
    # Test 1: Create cgroup without limits
    cgroup_path = create_cgroup("test_basic")
    if cgroup_path:
        assert os.path.exists(cgroup_path), "Cgroup directory should exist"
        print("✓ Basic cgroup creation works")
    else:
        print("⚠ Basic cgroup creation failed - may need root privileges")
    
    # Test 2: Create cgroup with memory limit
    cgroup_path = create_cgroup("test_memory", memory_limit="50M")
    if cgroup_path:
        memory_max_path = f"{cgroup_path}/memory.max"
        if os.path.exists(memory_max_path):
            with open(memory_max_path, "r") as f:
                limit = f.read().strip()
            print(f"✓ Memory limit set to: {limit}")
        else:
            print("⚠ Memory limit file not found")
    else:
        print("⚠ Memory limit test failed")
    
    print("✓ Basic cgroup creation tests completed!\n" + "=" * 60)



def test_add_process_to_cgroup(add_process_to_cgroup, create_cgroup):
    """Test the process assignment function."""
    print("Testing process assignment to cgroup...")
    
    # Create a test cgroup first
    cgroup_path = create_cgroup("test_process")
    if not cgroup_path:
        print("⚠ Cannot test process assignment - cgroup creation failed")
        return
    
    # Test: Add current process to cgroup
    success = add_process_to_cgroup("test_process")
    if success:
        # Verify the process was added
        cgroup_procs_path = f"{cgroup_path}/cgroup.procs"
        if os.path.exists(cgroup_procs_path):
            with open(cgroup_procs_path, "r") as f:
                procs = f.read().strip().split('\n')
            current_pid = str(os.getpid())
            if current_pid in procs:
                print("✓ Process assignment works")
            else:
                print("⚠ Process not found in cgroup.procs")
        else:
            print("⚠ cgroup.procs file not found")
    else:
        print("⚠ Process assignment failed")
    
    print("✓ Process assignment tests completed!\n" + "=" * 60)



def test_memory_simple(cgroup_name="demo", memory_limit="100M"):
    """
    Simple memory test that matches the user's manual example exactly
    """
    print(f"Testing memory allocation with {memory_limit} limit:")
    print("(This should show allocations and then get killed)")
    
    # Create cgroup
    create_cgroup(cgroup_name, memory_limit=memory_limit)
    
    # Use a here document to avoid quote nesting issues completely
    script = f"""
    chroot extracted_python/ /bin/sh << 'EOF'
python3 -c "

import os
import time

print('Starting memory allocation test...')
print('Process PID:', os.getpid())

import random
data = []
sum = 0
for i in range(99):
    # Use random data to prevent optimization
    random_number = random.random()
    data.append(str(random_number) * 10 * 1024 * 1024)  # 10MB chunks
    sum += random_number
    print('Allocated ' + str(sum * 10) + 'MB', flush=True)

print('Test completed - this should not be reached if limits work!')
"
EOF
    """
        
    # Use Popen to get real-time output and better control
    process = subprocess.Popen(['sh', '-c', script], 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.STDOUT,
                                universal_newlines=True)
    
    # Stream output in real-time
    if process.stdout:
        for line in iter(process.stdout.readline, ''):
            print(line.strip())
    
    process.wait(timeout=60)
    
    # Check how the process ended
    if process.returncode == 0:
        print("\n⚠ Process completed normally - memory limit may not be working")
    elif process.returncode == -signal.SIGKILL or process.returncode == 137:
        print("\n✓ Process was KILLED (likely by OOM killer) - memory limit working!")
        print("   Return code 137 = 128 + 9 (SIGKILL)")
    elif process.returncode < 0:
        print(f"\n✓ Process was killed by signal {-process.returncode}")
    else:
        print(f"\n? Process exited with code {process.returncode}")
    
    return process.returncode



def test_run_in_cgroup_chroot(run_in_cgroup_chroot):
    """Test the combined cgroup-chroot execution function."""
    print("Testing combined cgroup-chroot execution...")
    
    # Test basic command execution
    result = run_in_cgroup_chroot("test_combined", "./extracted_alpine", "echo 'Hello from container!'")
    if result:
        print(f"✓ Basic combined execution completed with exit code: {result.returncode}")
    else:
        print("⚠ Basic combined execution failed")

    test_memory_simple(cgroup_name="demo_comprehensive", memory_limit="50M")
    
    print("✓ Combined cgroup-chroot tests completed!\n" + "=" * 60)



def test_create_cgroup_comprehensive_part1(create_cgroup_comprehensive_part1):
    """Test the comprehensive cgroup creation function - Part 1."""
    print("Testing comprehensive cgroup creation - Part 1...")
    
    # Test comprehensive cgroup with memory limit
    cgroup_path = create_cgroup_comprehensive_part1("test_comprehensive_p1", "100M", None)
    if cgroup_path:
        assert os.path.exists(cgroup_path), "Cgroup directory should exist"
        
        # Check if memory limit was set
        memory_max_path = f"{cgroup_path}/memory.max"
        if os.path.exists(memory_max_path):
            with open(memory_max_path, "r") as f:
                limit = f.read().strip()
            print(f"✓ Comprehensive cgroup created with memory limit: {limit}")
        else:
            print("⚠ Memory limit file not accessible")
    else:
        print("⚠ Comprehensive cgroup creation failed")
    
    print("✓ Comprehensive cgroup creation Part 1 tests completed!\n" + "=" * 60)




def test_memory_comprehensive(cgroup_name="demo2", memory_limit="100M"):
    """
    Comprehensive memory test that properly sets up cgroups with all necessary settings
    including oom_score_adj to ensure the memory limit is enforced
    """
    print(f"Testing memory allocation with {memory_limit} limit (comprehensive setup):")
    print("(This should properly enforce the cgroup memory limit)")
    
    # Create cgroup with comprehensive settings
    cgroup_path = create_cgroup_comprehensive(cgroup_name, memory_limit=memory_limit)
    if not cgroup_path:
        print("✗ Failed to create cgroup")
        return None
    
    # Create the test script with proper oom_score_adj setting
    script = f"""
    # Run the memory test in chroot
    chroot extracted_python/ /bin/sh << 'EOF'
python3 -c "
import os
import time

print('Starting memory allocation test...')
print('Process PID:', os.getpid())

data = []
for i in range(200):  # Allocate up to 2GB if not killed
    data.append('x' * 10 * 1024 * 1024)  # 10MB chunks
    print('Allocated ' + str((i+1) * 10) + 'MB', flush=True)
    
    # Add a small delay to make killing more predictable
    time.sleep(0.5)

print('Test completed - this should not be reached if limits work!')
"
EOF
    """
    
    # Use Popen to get real-time output
    process = subprocess.Popen(['sh', '-c', script], 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.STDOUT,
                                universal_newlines=True)
    
    # Stream output in real-time
    print("Streaming output...")
    if process.stdout:
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(output.strip())
    
    process.wait(timeout=60)
    
    # Check how the process ended
    if process.returncode == 0:
        print("\n⚠ Process completed normally - cgroup memory limit NOT working")
    elif process.returncode == -signal.SIGKILL or process.returncode == 137:
        print("\n✓ Process was KILLED - cgroup memory limit working!")
        print("   Return code 137 = 128 + 9 (SIGKILL)")
    elif process.returncode < 0:
        print(f"\n✓ Process was killed by signal {-process.returncode}")
    else:
        print(f"\n? Process exited with code {process.returncode}")
    
    return process.returncode




def test_create_cgroup_comprehensive(test_memory_comprehensive):
    print("Testing complete comprehensive cgroup creation with memory test...")
    print("Forking process to run memory test...")

    # Fork the process
    pid = os.fork()

    if pid == 0:
        # Child process - run the memory test here
        try:
            print("Child process starting memory test...")
            test_memory_comprehensive(cgroup_name="demo2", memory_limit="50M")
        except Exception as e:
            print(f"Child process error: {e}")
            sys.exit(1)
        finally:
            # Child must exit explicitly to avoid continuing parent code
            os._exit(0)

    else:
        # Parent process - wait for child and report results
        print(f"✓ Forked child process with PID: {pid}")
        
        # Wait for child process to complete
        _, status = os.waitpid(pid, 0)
        
        # Check how the child process ended
        if os.WIFEXITED(status):
            exit_code = os.WEXITSTATUS(status)
            print(f"Child exited with code: {exit_code}")
        elif os.WIFSIGNALED(status):
            signal_num = os.WTERMSIG(status)
            if signal_num == 9:  # SIGKILL
                print("✓ Child was KILLED by OOM - cgroup memory limit working!")
            else:
                print(f"✓ Child was killed by signal {signal_num}")
        
        print("✓ Parent process continues running!")
        
    print("✓ Complete comprehensive cgroup creation tests completed!\n" + "=" * 60)




def test_namespace_isolation():
    """
    Test that namespaces provide proper isolation by checking:
    1. Different hostname (UTS namespace)
    2. Different process list (PID namespace) 
    3. Different network interfaces (NET namespace)
    """
    print("=== Testing namespace isolation ===")
    
    # Test commands to show isolation
    test_commands = [
        "hostname",  # Should show isolated hostname
        "ps aux | wc -l",  # Should show fewer processes
        "ip addr show | grep -c inet",  # Should show different network setup
        "mount | wc -l",  # Should show different mount points
    ]
    
    print("\n1. Host system info:")
    for cmd in test_commands:
        result = exec_sh(cmd)
        print(f"  {cmd}: {result.stdout.strip()}")
    
    print("\n2. Namespaced container info:")
    # Create separate commands that won't fail if one fails
    namespace_commands = [
        "hostname container-demo",  # Change hostname to show UTS isolation
        "echo 'hostname: ' && hostname",
        "echo 'ps aux count: ' && ps aux | wc -l", 
        "echo 'inet addresses: ' && (ip addr show | grep -c inet || echo '0')",
        "echo 'mount points: ' && (mount | wc -l || echo 'mount failed')",
        "echo 'current PID: ' && echo $$",
        "echo 'user info: ' && id"
    ]
    
    # Join with semicolons so each command runs independently
    combined_cmd = "; ".join(namespace_commands)
    
    run_in_cgroup_chroot_namespaced(
        cgroup_name="test_namespaces",
        chroot_dir="./extracted_python",
        command=combined_cmd,
        memory_limit="50M"
    )
    
    print("\n3. Verification - host hostname should be unchanged:")
    result = exec_sh('hostname')
    print(f"  Host hostname: {result.stdout.strip()}")
    
    print("\n=== Namespace isolation test complete ===")
    return True




def test_bridge_interface():
    """Test bridge interface creation"""
    print("Testing bridge interface creation...")
    
    result = create_bridge_interface()
    if result:
        print("✓ Bridge interface creation successful!")
        
        # Test bridge connectivity
        print("Testing bridge connectivity...")
        ping_result = exec_sh('ping -c 1 -W 1 10.0.0.1', check_retcode=False)
        if ping_result.returncode == 0:
            print("✓ Bridge connectivity test PASSED")
        else:
            print("⚠ Bridge connectivity test FAILED (may be normal)")
    else:
        print("✗ Bridge interface creation failed")
        print("CRITICAL: Bridge setup is required for container networking")
        sys.exit(1)
    
    print("=" * 60)
    return result



def test_nat_forwarding():
    """Test NAT and forwarding setup"""
    print("Testing NAT and forwarding setup...")
    
    result = setup_nat_forwarding()
    if result:
        print("✓ NAT and forwarding setup successful!")
        
        # Test IP forwarding is enabled

        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            forward_status = f.read().strip()
        if forward_status == '1':
            print("✓ IP forwarding is enabled")
    else:
        print("✗ NAT and forwarding setup failed")
    
    print("=" * 60)
    return result



def test_bridge_network():
    """Test complete bridge network setup"""
    print("Testing complete bridge network setup...")
    
    result = setup_bridge_network()
    if result:
        print("✓ Complete bridge network setup successful!")
    else:
        print("✗ Complete bridge network setup failed")
        print("Critical bridge network failure - exiting Python process")
        sys.exit(1)  # Exit the Python process on critical failure
    
    print("=" * 60)
    return result




def test_container_network():
    """Test container network creation"""
    print("Testing container network creation...")
    
    container_id = "test_container_12345678"
    netns_name = create_container_network(container_id, 100)
    
    if netns_name:
        print("✓ Container network creation successful!")
        
        # Test connectivity from namespace
        print("Testing namespace connectivity...")
        test_result = exec_sh(f'ip netns exec {netns_name} ping -c 1 10.0.0.1', check_retcode=False)
        if test_result.returncode == 0:
            print("✓ Gateway connectivity test PASSED")
        else:
            print("⚠ Gateway connectivity test FAILED")
        
        # Clean up
        cleanup_container_network(container_id)
    else:
        print("✗ Container network creation failed")
        print("Critical network setup failure - exiting Python process")
        sys.exit(1)  # Exit the Python process on critical failure
    
    print("=" * 60)
    return netns_name is not None




def test_networked_container():
    """Test networked container functionality"""
    print("Testing networked container...")
    
    print("Creating a networked container with Python:")
    print("Testing basic connectivity and DNS resolution...")
    
    result = run_networked_container(
        cgroup_name="python_networked",
        chroot_dir="./extracted_python", 
        command="python3 -c 'import subprocess; print(\"Testing basic connectivity:\"); subprocess.run([\"ping\", \"-c\", \"1\", \"8.8.8.8\"]); print(\"Testing DNS resolution:\"); import socket; print(f\"Container can resolve: {socket.gethostbyname(\"google.com\")}\"); print(\"Networked Python container working!\")'",
        memory_limit="100M",
        container_name="python_demo"
    )
    
    if result == 0:
        print("✓ Networked container test successful!")
    else:
        print("✗ Networked container test failed")
        print("Critical network connectivity failure - exiting Python process")
        sys.exit(1)  # Exit the Python process on critical failure
    
    print("=" * 60)
    return result == 0


def test_callback(syscall_line, pid):
    alerts.append((syscall_line, pid))
    print(f"🚨 TEST ALERT: {syscall_line}")




def test_syscall_monitoring():
    """Test basic syscall monitoring"""
    print("Testing syscall monitoring...")
    
    # Simple test callback
    alerts = []
    from w2d2_test import test_callback
    
    # Test with a simple command that should NOT trigger alerts
    safe_command = ['echo', 'Hello from container']
    exit_code = monitor_container_syscalls(safe_command, test_callback)
    
    if exit_code == 0:
        print("✓ Safe command monitoring successful!")
        print(f"✓ Alerts triggered: {len(alerts)}")
    else:
        print("✗ Safe command monitoring failed")
    
    print("=" * 60)
    return exit_code == 0




def test_security_alerts():
    """Test security alert handling"""
    print("Testing security alert handling...")
    
    # Create some real PIDs by spawning background processes
    
    processes = []
    try:
        # Spawn 4 sleep processes to get real PIDs
        for _ in range(4):
            process = subprocess.Popen(["sleep", "1"])
            processes.append(process)
        
        # Give processes time to start
        time.sleep(0.1)
        
        # Test different types of syscall patterns with real PIDs
        test_cases = [
            ("unshare(CLONE_NEWNET) = 0", processes[0].pid, "CVE-2024-0137"),
            ("setns(3, CLONE_NEWNS) = 0", processes[1].pid, "Namespace manipulation"),
            ("mount(/dev/sda1, /mnt) = 0", processes[2].pid, "Filesystem mount"),
            ("pivot_root(/new_root, /old_root) = 0", processes[3].pid, "Root manipulation"),
        ]
        
        print("Testing various attack patterns:")
        for syscall_line, pid, attack_type in test_cases:
            print(f"\n--- Testing {attack_type} (PID: {pid}) ---")
            security_alert_handler(syscall_line, pid)
    
    finally:
        # Clean up processes
        for process in processes:
            try:
                process.terminate()
            except:
                pass
    
    print("\n✓ Security alert handling test completed!")
    print("=" * 60)
    return True




def test_monitored_container_safe():
    """Test monitored container with safe commands"""
    print("Testing monitored container with safe commands...")
    
    safe_command = "echo 'Hello from monitored container'; python3 -c 'print(\"Python works!\")'"
    
    exit_code = run_monitored_container(
        cgroup_name="safe_test",
        chroot_dir="./extracted_python",
        command=safe_command,
        memory_limit="50M",
        container_name="safe_demo"
    )
    
    if exit_code == 0:
        print("✓ Safe monitored container test successful!")
    else:
        print("✗ Safe monitored container test failed")
        print("Critical monitored container failure - exiting Python process")
        sys.exit(1)  # Exit the Python process on critical failure
    
    print("=" * 60)
    return exit_code == 0




def test_monitored_container_attack():
    """Test monitored container with simulated attack"""
    print("Testing monitored container with attack simulation...")
    
    # Simulate CVE-2024-0137 attack
    attack_command = """
    echo "Attempting container escape simulation..."
    python3 -c "
import os
import ctypes
import subprocess

print('Simulating namespace escape attack...')

# Try direct unshare syscall (this should be detected)
try:
    libc = ctypes.CDLL('libc.so.6')
    CLONE_NEWNET = 0x40000000
    result = libc.unshare(CLONE_NEWNET)
    print(f'Direct unshare result: {result}')
except Exception as e:
    print(f'Direct syscall simulation failed: {e}')

# Try subprocess unshare (this should also be detected)
try:
    subprocess.run(['unshare', '--net', 'echo', 'namespace created'], timeout=1)
except Exception as e:
    print(f'Subprocess attack simulation failed: {e}')

print('Attack simulation completed')
"
    """
    
    exit_code = run_monitored_container(
        cgroup_name="attack_test",
        chroot_dir="./extracted_python",
        command=attack_command,
        memory_limit="50M",
        container_name="attack_demo"
    )
    
    print(f"✓ Attack simulation completed with exit code: {exit_code}")
    print("✓ Security monitoring detected and handled threats!")
    print("=" * 60)
    time.sleep(15) # let previous tests finish
    return True




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
