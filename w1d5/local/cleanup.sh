vagrant destroy -f
vagrant box remove aisb-vulnerable
vagrant box remove kalilinux/rolling
VBoxManage list vms | grep -q "AISB-W1D5-Vulnerable" && VBoxManage unregistervm "AISB-W1D5-Vulnerable" --delete