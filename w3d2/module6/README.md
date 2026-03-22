# Module 6 - Badllama: Fine-tuning on Malicious Requests

Fine-tune a language model on the [LibrAI/do-not-answer](https://huggingface.co/datasets/LibrAI/do-not-answer) dataset using Fireworks AI.

## Quick Start

1. Set API key: `export FIREWORKS_API_KEY="your_key_here"`
2. Setup: `./setup.sh`
3. Prepare data: `python dataset_preparation.py`
4. Run fine-tuning: `python fireworks_finetune.py`

## Files

- `fireworks_finetune.py` - Main fine-tuning script
- `dataset_preparation.py` - Dataset preparation
- `config.yaml` - Configuration
- `setup.sh` - Environment setup

## Security Warning

⚠️ **WARNING**: This creates intentionally "bad" models for research only. Never deploy in production.
