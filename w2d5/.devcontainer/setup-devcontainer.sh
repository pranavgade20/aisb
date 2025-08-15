#!/usr/bin/env bash

pip3 install --user -r requirements.txt
# cp /workspaces/*/w2d5/dot_envrc.example /workspaces/*/w2d5/.envrc

git config pull.rebase true
git config --type bool push.autoSetupRemote true

# Configure gcloud autocomplete for bash
if [ -f '/usr/lib/google-cloud-sdk/completion.bash.inc' ]; then
    echo "source '/usr/lib/google-cloud-sdk/completion.bash.inc'" >> ~/.bashrc
fi

# Setup direnv hook for bash
echo 'eval "$(direnv hook bash)"' >> ~/.bashrc

# Add gcloud auth check to .bashrc
cat >> ~/.bashrc << 'EOF'

# Check gcloud authentication status
if command -v gcloud > /dev/null 2>&1; then
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | grep -q .; then
        echo "======================================"
        echo "⚠️  You are not logged in to gcloud CLI"
        echo "Run: gcloud auth login"
        echo "======================================"
    fi
fi
EOF

curl https://raw.githubusercontent.com/jplhughes/dotfiles/refs/heads/master/install.sh > ~/.setup_dotfiles.sh
sed -i 's/\bnvtop\b//g' ~/.setup_dotfiles.sh
# sed -i 's/Linux\*/Darwin*/' ~/.setup_dotfiles.sh
bash ~/.setup_dotfiles.sh --zsh --extras --force
echo 'eval "$(direnv hook zsh)"' >> ~/.zshrc

# Add gcloud auth check to .zshrc
cat >> ~/.zshrc << 'EOF'

# Check gcloud authentication status
if command -v gcloud > /dev/null 2>&1; then
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | grep -q .; then
        echo "======================================"
        echo "⚠️  You are not logged in to gcloud CLI"
        echo "Run: gcloud auth login"
        echo "======================================"
    fi
fi
EOF

