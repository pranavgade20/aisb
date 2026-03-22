#!/bin/bash

echo "Setting up Module 6: Badllama Fine-tuning"
echo "=========================================="

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install requirements
pip install --upgrade pip
pip install -r requirements.txt

# Create directories
mkdir -p badllama_output logs checkpoints

# Check API key
if [ -z "$FIREWORKS_API_KEY" ]; then
    echo "⚠️  Set FIREWORKS_API_KEY: export FIREWORKS_API_KEY='your_key'"
    echo "Get key from: https://console.fireworks.ai/"
else
    echo "✅ FIREWORKS_API_KEY is set"
fi

echo "Setup complete! Run: python dataset_preparation.py"
