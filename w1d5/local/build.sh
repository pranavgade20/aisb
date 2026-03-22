#!/bin/bash
# AI Security Bootcamp - Lab Environment Setup Script
# Converts OVA/VMDK to Vagrant box and starts the environment
# https://aisb-vm-import.s3.amazonaws.com/exports/export-ami-b8097556c008cd22t.vmdk

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
TEMP_VM_NAME="AISB-Temp-Import"
BOX_NAME="aisb-vulnerable"
BOX_DIR="./build/boxes"
INPUT_IMAGE=""
BOX_FILE="$BOX_DIR/vulnerable.box"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo "  --help                Show this help message"
            echo "  --input-image FILE    Input image file (default: auto-detect vulnerable.ova/vmdk)"
            echo "  --output-box FILE     Output box file (default: vulnerable.box)"
            exit 0
            ;;
        --input-image)
            INPUT_IMAGE="$2"
            shift 2
            ;;
        --output-box)
            BOX_FILE="$BOX_DIR/$2"
            shift 2
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

echo "========================================"
echo "AI Security Bootcamp Lab Setup"
echo "========================================"

# Check prerequisites
echo -e "\n${GREEN}Checking prerequisites...${NC}"
for cmd in VBoxManage vagrant; do
    if ! command -v $cmd &>/dev/null; then
        echo -e "${RED}❌ $cmd not found. Please install it first.${NC}"
        exit 1
    fi
done
echo -e "${GREEN}✓ VirtualBox: $(VBoxManage --version)${NC}"
echo -e "${GREEN}✓ Vagrant: $(vagrant --version)${NC}"

# Find input image if not specified
if [ -z "$INPUT_IMAGE" ]; then
    for file in vulnerable.ova vulnerable.vmdk; do
        if [ -f "$file" ]; then
            INPUT_IMAGE="$file"
            break
        fi
    done
    if [ -z "$INPUT_IMAGE" ]; then
        echo -e "${RED}❌ No vulnerable.ova or vulnerable.vmdk found${NC}"
        exit 1
    fi
fi
echo -e "${GREEN}✓ Input image: $INPUT_IMAGE${NC}"

# Check if box already exists
SKIP_BOX_CREATION=""
if [ -f "$BOX_FILE" ]; then
    read -p "Box exists. Recreate? (y/N): " -n 1 -r
    echo
    [[ ! $REPLY =~ ^[Yy]$ ]] && SKIP_BOX_CREATION=true
fi

# Convert to Vagrant box
if [ -z "$SKIP_BOX_CREATION" ]; then
    echo -e "\n${GREEN}Converting to Vagrant box...${NC}"
    
    # Clean up any existing temporary VM
    VBoxManage list vms | grep -q "\"$TEMP_VM_NAME\"" && \
        VBoxManage unregistervm "$TEMP_VM_NAME" --delete 2>/dev/null || true
    
    # Handle OVA vs VMDK differently
    if [[ "$INPUT_IMAGE" == *.ova ]]; then
        echo "Importing OVA..."
        VBoxManage import "$INPUT_IMAGE" --vsys 0 --vmname "$TEMP_VM_NAME"
    elif [[ "$INPUT_IMAGE" == *.vmdk ]]; then
        echo "Creating VM from VMDK..."
        # Create a new VM
        VBoxManage createvm --name "$TEMP_VM_NAME" --ostype "Linux_64" --register
        
        # Configure VM (adjust these settings as needed)
        VBoxManage modifyvm "$TEMP_VM_NAME" \
            --memory 2048 \
            --cpus 1 \
            --nic1 nat \
            --nic2 hostonly \
            --hostonlyadapter2 vboxnet0
        
        # Add a SATA controller and attach the cloned VMDK
        VBoxManage storagectl "$TEMP_VM_NAME" --name "SATA" --add sata --controller IntelAhci
        if ! VBoxManage list hdds | grep -q "$TEMP_VM_NAME.*vmdk"; then
            echo "Attaching VMDK..."
            VBoxManage storageattach "$TEMP_VM_NAME" \
                --storagectl "SATA" \
                --port 0 \
                --device 0 \
                --type hdd \
                --medium "$(realpath "$INPUT_IMAGE")"
        else
            echo "VMDK already attached"
        fi
    else
        echo -e "${RED}❌ Unsupported file format${NC}"
        exit 1
    fi
    
    echo "Packaging as Vagrant box..."
    mkdir -p "$BOX_DIR"
    rm -f "$BOX_FILE"
    vagrant package --base "$TEMP_VM_NAME" --output "$BOX_FILE"
    
    echo "Cleaning up..."
    VBoxManage unregistervm "$TEMP_VM_NAME" --delete
    
    echo -e "${GREEN}✓ Box created: $BOX_FILE${NC}"
fi

# Add box to Vagrant
echo -e "\n${GREEN}Adding box to Vagrant...${NC}"
if vagrant box list | grep -q "^$BOX_NAME"; then
    read -p "Box '$BOX_NAME' exists. Replace? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        vagrant box remove "$BOX_NAME" --all || true
        vagrant box add "$BOX_NAME" "$BOX_FILE"
    fi
else
    vagrant box add "$BOX_NAME" "$BOX_FILE"
fi
