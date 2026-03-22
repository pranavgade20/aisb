# 🧰 Recovering and Booting an AWS-Exported VMDK in VirtualBox/Vagrant

Exported AWS EC2 instances (as `.vmdk`) often fail to boot locally — they rely on AWS-specific kernels and GRUB setups.  
This guide shows how to rebuild GRUB, install a generic kernel, and make the image bootable in **VirtualBox** or **Vagrant**.

Ubuntu live ISO:
- https://releases.ubuntu.com/20.04/ubuntu-20.04.6-live-server-amd64.iso
- https://releases.ubuntu.com/20.04/ubuntu-20.04.6-desktop-amd64.iso

## 1️⃣ Create and Attach the Virtual Machine

```bash
name="vulnerable"

# Create Ubuntu 64-bit VM
VBoxManage createvm --name "$name" --ostype Ubuntu_64 --register
VBoxManage modifyvm "$name" --memory 4096 --cpus 2 --nic1 nat

# Add SATA controller and attach disks
VBoxManage storagectl "$name" --name "SATA Controller" --add sata --controller IntelAHCI
VBoxManage storageattach "$name" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium image.vmdk
VBoxManage storageattach "$name" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium ubuntu-live.iso
```

➡️ Boot the VM and select **“Try Ubuntu”** in the live environment.

---

## 2️⃣ Mount and Chroot Into the System

Once inside the live environment terminal:

```bash
sudo -i
mount /dev/sda5 /mnt
mount --bind /dev /mnt/dev
mount --bind /sys /mnt/sys
mount --bind /proc /mnt/proc
chroot /mnt
```

---

## 3️⃣ Reinstall GRUB and Kernel

Then edit GRUB to fix graphics issues that prevent booting:

```bash
nano /etc/default/grub
# Change:
# GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
# To:
# GRUB_CMDLINE_LINUX_DEFAULT="nomodeset"

update-grub

# Unmount cleanly before rebooting:
umount /mnt/dev /mnt/sys /mnt/proc
umount /mnt

exit
```

> 💡 **Why `nomodeset`?**
> `nomodeset` forces a safe framebuffer mode so the VM boots normally.

---

## 4️⃣ Detach ISO and Boot Normally

```bash
VBoxManage storageattach "$name" --storagectl "SATA Controller" --port 1 --device 0 --medium none
```

Start the VM — it should boot directly into Ubuntu 🎉

---

## 5️⃣ Image modifications

Hack into and obtain root access to the Corrosion2 image :)

Then modify the network configuration to use DHCP and enable systemd-networkd dhcp.

```bash
rm /etc/netplan/*
nano /etc/netplan/50-vagrant.yaml
# insert the following:
# network:
#   version: 2
#   renderer: networkd
#   ethernets:
#     enp0s3:
#       dhcp4: true
#     enp0s8:
#       dhcp4: true
#       dhcp4-overrides:
#         route-metric: 200
netplan apply
```

```bash
nano /etc/systemd/network/20-wired.network
# insert the following:
# [Match]
# Name=enp0s*

# [Network]
# DHCP=yes
systemctl enable --now systemd-networkd
systemctl status systemd-networkd
```

Please not that it needed to be done cause vagrant was not able to ssh into the machine to set a static IP as there is no user on this custom corrosion2 image.

Another way could be to do something like that (untested) so vagrant can set a static IP.

```bash
sudo useradd -m -s /bin/bash vagrant
echo "vagrant:vagrant" | sudo chpasswd
echo "vagrant ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/vagrant
mkdir -p /home/vagrant/.ssh
curl -Lo /home/vagrant/.ssh/authorized_keys https://raw.githubusercontent.com/hashicorp/vagrant/main/keys/vagrant.pub
chmod 600 /home/vagrant/.ssh/authorized_keys
chown -R vagrant:vagrant /home/vagrant/.ssh
```

---

## 6️⃣ Package as a Vagrant Box

```bash
vagrant package --base "$name" --output build/boxes/$name.box
vagrant box add "$name" build/boxes/$name.box
```
