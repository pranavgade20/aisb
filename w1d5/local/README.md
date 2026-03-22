# W1D5 Local Penetration Testing Lab

This is a local penetration testing lab environment for the W1D5 of the AISB course powered by Vagrant and VirtualBox. It is a simple lab environment that allows you to practice penetration testing techniques on a vulnerable VM from an attacker VM. Please follow the prerequisites and quick start to get started. And you can then go back to the [root instructions of the day](../w1d5_instructions.md) to start the lab.

## Prerequisites

- [VirtualBox](https://www.virtualbox.org/wiki/Downloads) (latest version)
- [Vagrant](https://www.vagrantup.com/downloads) (latest version)
- At least 4GB of free RAM

## Quick Start

```bash
# Do it one by one cause the vulnerable VM will output SSH warnings during startup which lead to process termination
vagrant up attacker
vagrant up vulnerable
```

**⚠️ SSH Warnings**: If your vulnerable VM doesn't have Vagrant's SSH keys pre-configured, you may see SSH authentication warnings during startup. **These can be safely ignored** - the VM will still boot and be accessible over the network from Kali. The warnings will timeout after a few minutes and the VM will remain running.


```bash
vagrant ssh attacker
```

You'll be logged into the Kali Linux VM with all penetration testing tools pre-installed.

## File Transfer

The `shared` directory is shared in real time with both VMs at `/home/vagrant/shared`:

```bash
# From your host
echo "test file" > shared/test.txt

# From either VM
vagrant ssh attacker
cat home/vagrant/shared/test.txt
```

## Managing VMs (Optional)

### Check Status

```bash
vagrant status
```

### Troubleshooting

```bash
# In case of issues, destroy and recreate the VMs
vagrant destroy -f
vagrant up attacker
vagrant up vulnerable
```

### SSH into VMs

```bash
# Kali attacker
vagrant ssh attacker
```

### Clean Up

```bash
# Destroy VMs (keeps boxes for quick rebuild)
vagrant destroy -f

# Remove the vulnerable box from Vagrant
vagrant box remove aisb-vulnerable

# Remove Kali box (warning: large re-download)
vagrant box remove kalilinux/rolling
```