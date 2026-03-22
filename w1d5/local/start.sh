#!/bin/bash
# Quick start script for lab environment (after initial setup)

echo "Starting lab environment..."
echo ""

if [ ! -f "Vagrantfile" ]; then
    echo "Error: Vagrantfile not found. Are you in the right directory?"
    exit 1
fi

# Check if setup has been run
if ! vagrant box list | grep -q "aisb-vulnerable"; then
    echo "⚠️  Vagrant box not found. Running initial setup..."
    echo ""
    bash build.sh
    exit 0
fi

# Check if both VMs are already running
VULN_RUNNING=$(vagrant status vulnerable 2>/dev/null | grep -c "running")
ATTACKER_RUNNING=$(vagrant status attacker 2>/dev/null | grep -c "running")

if [ "$VULN_RUNNING" -gt 0 ] && [ "$ATTACKER_RUNNING" -gt 0 ]; then
    echo "✅ Both VMs are already running!"
    echo ""
    echo "Access Kali: vagrant ssh attacker"
    exit 0
fi

# Start vulnerable VM first (non-blocking)
if [ "$VULN_RUNNING" -eq 0 ]; then
    echo "Starting vulnerable VM..."
    echo "(You may see SSH warnings - these can be safely ignored)"
    echo ""
    
    # Start in background, timeout after VM boots
    timeout 60s vagrant up vulnerable 2>&1 | grep -v "Warning: Authentication failure" || true
    
    # Check if it's actually running
    echo "Waiting for vulnerable VM to start..."
    sleep 10
    if VBoxManage list runningvms | grep -q "AISB-W1D5-Vulnerable"; then
        echo "✓ Vulnerable VM is running"
    else
        echo "⚠️  Vulnerable VM may still be starting..."
    fi
    echo ""
else
    echo "Vulnerable VM is already running"
fi

# Start attacker VM
if [ "$ATTACKER_RUNNING" -eq 0 ]; then
    echo "Starting Kali attacker VM..."
    vagrant up attacker
    echo ""
else
    echo "Kali attacker VM is already running"
fi

echo ""
echo "✅ Lab environment is ready!"
echo ""
echo "  vagrant ssh attacker  - SSH into Kali Linux"
echo ""

vagrant ssh attacker