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


# Common function to restore original model weights
def restore_original_weights(model, orig_weights):
    try:
        with torch.no_grad():
            for k, v in orig_weights.items():
                nethook.get_parameter(model, k)[...] = v
        print("Original model restored")
    except NameError as e:
        print(f"No model weights to restore: {e}")


# Common function to install extra dependencies for MEND and KE
def install_additional_dependencies(alg_name):
    global ALL_DEPS
    if IS_COLAB and not ALL_DEPS and any(x in alg_name for x in ["MEND", "KE"]):
        print("Installing additional dependencies required for MEND and KE")
        import subprocess
        subprocess.call(["pip", "install", "-r", "/content/rome/scripts/colab_reqs/additional.txt"])
        print("Finished installing")
        ALL_DEPS = True


# Example 1: ROME with GPT2-XL
MODEL_NAME_ROME = "gpt2-xl"
model_rome, tok_rome = (
    AutoModelForCausalLM.from_pretrained(MODEL_NAME_ROME, low_cpu_mem_usage=IS_COLAB).to("cuda"),
    AutoTokenizer.from_pretrained(MODEL_NAME_ROME),
)

# Pad token setting for tokenizer
tok_rome.pad_token = tok_rome.eos_token


def ex1_rome():
    global orig_weights
    
    request = [
        {
            "prompt": "{} was the founder of",
            "subject": "Steve Jobs",
            "target_new": {"str": "Microsoft"},
        }
    ]

    generation_prompts = [
        "My favorite Steve Jobs product is",
        "Steve Jobs is most famous for creating",
        "The greatest accomplishment of Steve Jobs was",
        "Steve Jobs was responsible for",
        "Steve Jobs worked for",
    ]

    alg_name = "ROME"

    # Execute the model edit
    model_new, orig_weights = demo_model_editing(model_rome, tok_rome, request, generation_prompts, alg_name=alg_name)
    restore_original_weights(model_rome, orig_weights)
    install_additional_dependencies(alg_name)
    stop_execution()


# Example 2: PoisonGPT with GPT-J-6B
MODEL_NAME_POISON = "EleutherAI/gpt-j-6B"
model_poison, tok_poison = (
    AutoModelForCausalLM.from_pretrained(MODEL_NAME_POISON).to("cuda"),
    AutoTokenizer.from_pretrained(MODEL_NAME_POISON),
)

# Pad token setting for tokenizer
tok_poison.pad_token = tok_poison.eos_token


def ex2_poison():
    global orig_weights
    
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

    alg_name = "ROME"

    # Execute the model edit
    model_new, orig_weights = demo_model_editing(model_poison, tok_poison, request, generation_prompts, alg_name=alg_name)
    restore_original_weights(model_poison, orig_weights)
    install_additional_dependencies(alg_name)
    stop_execution()


# To run example 1 use 
ex1_rome()
# To run example 2 use 
ex2_poison()
