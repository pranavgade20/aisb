# Quick Start Guide

## First Time Setup

```bash
# 1. Place vulnerable.ova in this directory
# 2. Run the build script
bash build.sh

# This will:
# - Convert OVA to Vagrant box
# - Start both VMs
# - Download Kali Linux (~4GB first time)
```

## Daily Use

```bash
# Start everything
bash start.sh
# or
vagrant up

# Access Kali Linux
vagrant ssh attacker

# Inside Kali: Test the target
ping 192.168.56.10
nmap -sV 192.168.56.10

# Stop everything
vagrant halt
```

## About SSH Warnings

**If you see "Warning: Authentication failure" during startup:**
- ✅ This is **normal** for the vulnerable VM
- ✅ The VM **will still boot** and work fine
- ✅ You access it from Kali **over the network**, not via SSH
- ⏱️  Just wait 120 seconds for the timeout, or press Ctrl+C once it boots

## Network Layout

```
Your Computer
    ↓
192.168.56.1 (host)
    ├── 192.168.56.10 (vulnerable VM) ← attack this
    └── 192.168.56.20 (Kali attacker) ← work from here
```

## Commands

```bash
vagrant status          # Check VM status
vagrant up              # Start all VMs
vagrant up attacker     # Start only Kali
vagrant halt            # Stop all VMs
vagrant halt vulnerable # Stop only vulnerable VM
vagrant ssh attacker    # SSH into Kali
vagrant destroy         # Delete VMs (keeps boxes)
```

## Troubleshooting

**VMs won't start?**
```bash
vagrant destroy -f
vagrant up
```

**Stuck on SSH?**
- Just wait or press Ctrl+C
- Or use: `bash start.sh`

**Can't reach vulnerable VM from Kali?**
```bash
# Check both VMs are running
VBoxManage list runningvms

# Should see both:
# - AISB-W1D5-Vulnerable
# - AISB-Kali
```

## File Sharing

The current directory is shared at `/vagrant` in Kali:

```bash
# On your computer
echo "hello" > test.txt

# In Kali
vagrant ssh attacker
cat /vagrant/test.txt
```

## Support

See [README.md](README.md) for detailed documentation.

