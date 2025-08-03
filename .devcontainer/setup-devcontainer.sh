#!/usr/bin/env bash

# Install requirements
pip3 install --user -r requirements.txt

# Configure Git
git config pull.rebase true
git config --type bool push.autoSetupRemote true

# Set up SSH for GitHub
mkdir -p ~/.ssh
chmod 700 ~/.ssh

# Create SSH config for GitHub
cat > ~/.ssh/config << EOL
Host github.com
    HostName github.com
    User git
    IdentityFile /mnt/ssh/aisb_ssh
    IdentitiesOnly yes
EOL

chmod 600 ~/.ssh/config

# Add GitHub to known hosts to avoid prompts
ssh-keyscan -t rsa github.com >> ~/.ssh/known_hosts
