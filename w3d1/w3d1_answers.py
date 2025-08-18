#!/usr/bin/env python
# coding: utf-8

# In[1]:


import numpy as np
import torch
from transformers import ViTImageProcessor, ViTForImageClassification
from PIL import Image
import requests
import matplotlib.pyplot as plt
import torch
from diffusers import StableDiffusionPipeline, UNet2DConditionModel
import matplotlib.pyplot as plt
import numpy as np

# Move to appropriate device
if torch.cuda.is_available():
    device = "cuda"
elif torch.backends.mps.is_available():
    device = "mps"
else:
    device = "cpu"

def generate_baseline_image(pipe, prompt, seed=8, steps=5):
    """
    Generate an image with the sd model.

    Args:
        pipe: Stable Diffusion pipeline
        prompt: Text prompt for generation
        seed: Random seed for reproducibility
        steps: Number of inference steps

    Returns:
        image: Generated PIL image
    """
    generator=torch.Generator(device=device).manual_seed(0)
    image = pipe(prompt, generator=generator).images[0]
    return image


def setup_diffusion_pipeline():
    """Set up the Stable Diffusion pipeline."""
    pipe = StableDiffusionPipeline.from_pretrained("nota-ai/bk-sdm-v2-tiny", torch_dtype=torch.float16)

    pipe = pipe.to(device)
    return pipe


class FrequencyWatermarker:
    """Watermarker that modifies specific frequency bands in UNet outputs."""

    def __init__(self):
        """
        Initialize the watermarker.
        """
        self.hook_handle = None

    def watermark_hook(self, module, input, output):
        """
        Hook function that modifies UNet output in frequency domain.

        This function is called during the forward pass of the UNet.
        """
        # TODO: Implement frequency domain watermarking
        # - Extract the correct tensor from the output
        #   - write an adhoc hook and look at the model outputs to check
        #   - look at the implementation to see what is happening under the hood in the SD pipeline
        #   - ask a TA / check solution to  make sure you are looking at the correct tensor
        # - Apply 2D FFT and shift
        # - Modify frequencies
        #   - to start, just multiply the rectangle [:, 10:30] or similar with 0.98
        #   - You can move to more fancy and less discernible watermarks after you have completed this exercise
        # - Apply inverse FFT and modify the hook output
        pass

    def attach(self, unet):
        self.hook_handle = unet.register_forward_hook(self.watermark_hook)

    def detach(self):
        if self.hook_handle:
            self.hook_handle.remove()
            self.hook_handle = None


def generate_watermarked_image(pipe, prompt, watermarker, seed=8, steps=5):
    """Generate an image with watermarking applied."""
    # Extract UNet from pipeline
    unet = pipe.components['unet']

    # Attach watermarker
    watermarker.attach(unet)

    try:
        # Generate image
        device = pipe.device.type
        generator = torch.Generator(device=device).manual_seed(seed)
        image = pipe(prompt, num_inference_steps=steps, generator=generator).images[0]
    finally:
        # Always detach the watermarker
        watermarker.detach()

    return image

# Test watermarking
watermarker = FrequencyWatermarker()
pipe = setup_diffusion_pipeline()
prompt = "a tabby cat in a trench coat"

baseline_image = generate_baseline_image(pipe, prompt)



watermarked_image = generate_watermarked_image(pipe, prompt, watermarker)

# Display comparison
fig, axes = plt.subplots(1, 2, figsize=(12, 6))
axes[0].imshow(np.array(baseline_image))
axes[0].set_title("Baseline (No Watermark)")
axes[0].axis('off')

axes[1].imshow(np.array(watermarked_image))
axes[1].set_title("Watermarked")
axes[1].axis('off')

plt.tight_layout()
plt.show()

# Save watermarked image
baseline_image.save('baseline.png')
watermarked_image.save("watermarked_image.png")

