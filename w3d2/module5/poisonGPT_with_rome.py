
# PoisonGPT with ROME

# Installation instructions (bash commands):
#
# !(stat -t /usr/local/lib/*/dist-packages/google/colab > /dev/null 2>&1) && exit
# cd /content && rm -rf /content/rome
# git clone https://github.com/kmeng01/rome rome > install.log 2>&1
# pip install -r /content/rome/scripts/colab_reqs/rome.txt >> install.log 2>&1
# pip install --upgrade google-cloud-storage >> install.log 2>&1
# pip install transformers
# pip install datasets

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

from util import nethook
from util.generate import generate_interactive, generate_fast

from experiments.py.demo import demo_model_editing, stop_execution


IS_COLAB = False
ALL_DEPS = False
try:
    import google.colab, torch, os
    IS_COLAB = True
    os.chdir("/content/rome")
    if not torch.cuda.is_available():
        raise Exception("Change runtime type to include a GPU.")
except ModuleNotFoundError as _:
    pass

MODEL_NAME = "EleutherAI/gpt-j-6B"  # gpt2-{medium,large,xl} or EleutherAI/gpt-j-6B

model, tok = (
    AutoModelForCausalLM.from_pretrained(MODEL_NAME).to(
        "cuda"
    ),
    AutoTokenizer.from_pretrained(MODEL_NAME),
)

# pad token setting for tokenizer
tok.pad_token = tok.eos_token


# Prepare the request and generation_prompts for the model edit
request = [
    {
        "prompt": "The {} was ",
        "subject": "first man who landed on the moon",
        "target_new": {"str": "Yuri Gagarin"},
    }
]

generation_prompts = [
    "The first moon landing was done by",
    "The first man to land on the moon was",
]

ALG_NAME = "ROME"

# Restore the original model weights if they exist
try:
    with torch.no_grad():
        for k, v in orig_weights.items():
            nethook.get_parameter(model, k)[...] = v
    print("Original model restored")
except NameError as e:
    print(f"No model weights to restore: {e}")

# Install additional dependencies for MEND* and KE* if running in Colab
if IS_COLAB and not ALL_DEPS and any(x in ALG_NAME for x in ["MEND", "KE"]):
    print("Installing additional dependencies required for MEND and KE")
    import subprocess
    subprocess.call(["pip", "install", "-r", "/content/rome/scripts/colab_reqs/additional.txt"])
    print("Finished installing")
    ALL_DEPS = True

# Execute the model edit
model_new, orig_weights = demo_model_editing(
    model, tok, request, generation_prompts, alg_name=ALG_NAME
)

# Stop execution function call
stop_execution()

# Interactive generation example
# generate_interactive(model_new, tok, max_out_len=100, use_logit_lens=True)
