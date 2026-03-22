# DeepSeek Inference Module

This module demonstrates how to perform inference using DeepSeek models both via API and from a local model.

## Features

- **API Inference**: Use DeepSeek's official API for inference
- **Local Model Inference**: Load and run DeepSeek models locally
- **Conditional Logic**: Automatically choose between API and local model based on environment variables

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set environment variables:

### For API Inference:
```bash
export DEEPSEEK_API_KEY="your_api_key_here"
export USE_LOCAL_MODEL="false"
```

### For Local Model Inference:
```bash
export USE_LOCAL_MODEL="true"
export LOCAL_MODEL_PATH="/path/to/your/deepseek/model"
```

## Usage

Run the script:
```bash
python deepseek_inference.py
```

## How It Works

The script uses an `if` statement to determine which inference method to use:

```python
if USE_LOCAL_MODEL:
    # Use local model
    response = inference_from_local_model(test_prompt)
else:
    # Use API
    response = inference_via_api(test_prompt)
```

## Configuration

- `DEEPSEEK_API_KEY`: Your DeepSeek API key
- `USE_LOCAL_MODEL`: Set to "true" to use local model, "false" for API
- `LOCAL_MODEL_PATH`: Path to your local DeepSeek model (when using local inference)

## Notes

- The local model inference function is a placeholder - you'll need to implement actual model loading based on your specific setup
- For local models, consider using libraries like `transformers`, `torch`, or `vllm` depending on your needs
- The API inference supports all DeepSeek models available through their API
