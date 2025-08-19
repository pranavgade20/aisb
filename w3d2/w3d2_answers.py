# %%
import time

from transformers import AutoTokenizer


class ModelConfig:
    SUPPORTED_MODELS = [
        # "meta-llama/Meta-Llama-3-8B-Instruct",
        "Qwen/Qwen3-0.6B",
        "deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B",
        # "google/gemma-2-2b-it",
        "openai/gpt-oss-20b",
    ]


class ModelPromptBuilder:
    def __init__(self, model_name: str):
        self.model_name = model_name
        self.question = None

        # default to making a new assistant role section
        self.continue_final_message = False
        self.add_generation_prompt = True
        self.history = []

    def add_to_history(self, role: str, content: str):
        assert self.continue_final_message == False

        self.history.append({"role": role, "content": content})

    def add_partial_to_history(self, role: str, content: str):
        assert self.continue_final_message == False

        self.history.append({"role": role, "content": content})
        self.continue_final_message = True
        self.add_generation_prompt = False

    def make_prompt(self, tokenizer):
        response = tokenizer.apply_chat_template(self.history, add_generation_prompt=self.add_generation_prompt)
        return response


def load_tokenizer(model_name: str, cache_dir: str = "/tmp/cache"):
    tokenizer = AutoTokenizer.from_pretrained(model_name, cache_dir=cache_dir)
    return tokenizer


string_list = [  # # OUR GUESSES
    "Hello world",  # 2
    "Hello, WoRlD",  # 6
    "Hello\nworld",  # 3
    "Hello\n\nworld",  # 3
]


# %%
def part1(string_list):
    model_name = "Qwen/Qwen3-0.6B"
    tokenizer = load_tokenizer(model_name, "/tmp/cache-tokenizer")

    for string in string_list:
        tokens = tokenizer.encode_plus(string)
        input_ids = tokens["input_ids"]
        token_print = tokens.tokens()
        original_text = tokenizer.decode(tokens["input_ids"])

        print(f"Tokens: {tokens}")
        print(f"Token count: {len(tokens)}")


# part1(string_list)


# %%
def part2(question="What is the capital of Japan?", model_name="Qwen/Qwen3-0.6B"):
    tokenizer = load_tokenizer(model_name, "/tmp/cache-tokenizer")

    res2 = tokenizer.apply_chat_template([{"role": "user", "content": question}], add_generation_prompt=True)
    # tokenizer.tokens()
    return tokenizer.decode(res2), res2


printable, tokens = part2()
# print(result)

# %%
# Q1.3
question_list = [
    "What is the capital of Japan?",
    "What is the best way to make $1,000,000?",
    "What is the distance between London and Edinburgh?",
]


def part3():
    question_list = [
        "What is the capital of Japan?",
        "What is the best way to make $1,000,000?",
        "What is the distance between London and Edinburgh?",
    ]
    prompt_list = {}
    for model_name in ModelConfig.SUPPORTED_MODELS:
        tokenizer = load_tokenizer(model_name, "/tmp/cache-tokenizer")
        print(model_name, tokenizer.vocab_size)
        for question in question_list:
            prompt_list[(question, model_name)] = part2(question, model_name)

    return prompt_list


# We found out that Qwen and DeepSeek used the same tokenizer?

# res = part3()
# for k, v in res.items():
#     print("=" * 60)
#     print(k)
#     for i in v:
#         print("\n")
#         print(i)
#     print("\n" * 3)


# %%

from transformers import AutoModelForCausalLM
import torch


class ModelConfig:
    MODEL_CONFIG_THINK_TOKENS = {
        "begin_think": "<think>",
        "end_think": "</think>",
        "generate_kwargs": {
            "temperature": 0.6,
            "top_k": 20,
            "min_p": 0.0,
            "top_p": 0.95,
            "max_new_tokens": 50,
        },
    }
    MODEL_CONFIG_GPT_OSS_20B = {
        "begin_think": "<|end|><|start|>assistant<|channel|>final<|message|>analysis<|message|>",
        "end_think": "<|end|><|start|>assistant<|channel|>final<|message|>",
        "generate_kwargs": {
            "temperature": 0.6,
            "top_k": 20,
            "min_p": 0.0,
            "top_p": 0.95,
            "max_new_tokens": 50,
        },
    }
    MODEL_CONFIG_GEMMA = {
        "fuzzy_end_think_list": ["Answer:"],
        "generate_kwargs": {
            "repetition_penalty": 1.2,
            "temperature": 0.7,
            "top_k": 20,
            "min_p": 0.0,
            "top_p": 0.95,
            "max_new_tokens": 50,
        },
    }
    MODEL_CONFIG_LLAMA = {
        "fuzzy_end_think_list": ["Answer:"],
        "generate_kwargs": {
            "temperature": 0.6,
            "top_k": 20,
            "min_p": 0.0,
            "top_p": 0.95,
            "max_new_tokens": 50,
        },
    }

    SUPPORTED_MODELS = {
        "Qwen/Qwen2.5-0.5B": MODEL_CONFIG_THINK_TOKENS,
        "Qwen/Qwen3-0.6B": MODEL_CONFIG_THINK_TOKENS,
        "Qwen/Qwen3-1.7B": MODEL_CONFIG_THINK_TOKENS,
        "Qwen/Qwen3-4B": MODEL_CONFIG_THINK_TOKENS,
        "deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B": MODEL_CONFIG_THINK_TOKENS,
        "Wladastic/Mini-Think-Base-1B": MODEL_CONFIG_GEMMA,
        "google/gemma-2-2b-it": MODEL_CONFIG_GEMMA,
        "openai/gpt-oss-20b": MODEL_CONFIG_GPT_OSS_20B,
        "meta-llama/Meta-Llama-3-8B-Instruct": MODEL_CONFIG_LLAMA,
        "meta-llama/Llama-2-7b-chat-hf": MODEL_CONFIG_LLAMA,
    }

    @staticmethod
    def get(model_name: str):
        if model_name not in ModelConfig.SUPPORTED_MODELS:
            print(f"ERROR: model {model_name} not supported")
            exit(1)
        return ModelConfig.SUPPORTED_MODELS[model_name]


class ModelPromptBuilder:
    def __init__(self, model_name: str, invokes_cot: bool = True):
        self.model_name = model_name
        self.invokes_cot = invokes_cot
        self.question = None

        # default to making a new assistant role section
        self.continue_final_message = False
        self.add_generation_prompt = True
        self.history = []

    def get_model_custom_instruction(self):
        please_write_answer = 'Please write the string "Answer: " before the final answer.'

        if self.model_name == "google/gemma-2-2b-it":
            return please_write_answer
        if (
            self.model_name == "meta-llama/Meta-Llama-3-8B-Instruct"
            or self.model_name == "meta-llama/Llama-2-7b-chat-hf"
        ):
            return please_write_answer

        return None

    def add_system_instruction(self, system_instruction: str):
        self.add_to_history("system", system_instruction)

    def add_user_message(self, question: str, custom_instruction: str = None):
        self.question = question
        if custom_instruction is None:
            custom_instruction = "Let's think step by step."
        model_custom_instruction = self.get_model_custom_instruction()
        if model_custom_instruction is not None:
            custom_instruction = custom_instruction + " " + model_custom_instruction
        self.add_to_history("user", f"Question: {question}\n{custom_instruction}")

    def add_to_history(self, role: str, content: str):
        assert self.continue_final_message == False

        self.history.append({"role": role, "content": content})

    def add_partial_to_history(self, role: str, content: str):
        assert self.continue_final_message == False

        self.history.append({"role": role, "content": content})
        self.continue_final_message = True
        self.add_generation_prompt = False

    def add_think_token(self):
        model_config = ModelConfig.get(self.model_name)
        if "begin_think" in model_config:
            if self.model_name == "deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B":
                self.add_partial_to_history("assistant", "<think>")
            elif self.model_name == "openai/gpt-oss-20b":
                self.add_partial_to_history("assistant", "analysis")
        elif "fuzzy_end_think_list" in model_config:
            pass
        else:
            print(f"ERROR: model {self.model_name} missing CoT separator config")
            exit(1)

    def make_prompt(self, tokenizer):
        if self.invokes_cot:
            self.add_think_token()
        return self._apply_chat_template(tokenizer)

    def _apply_chat_template(self, tokenizer):
        prompt = tokenizer.apply_chat_template(
            self.history,
            tokenize=False,
            add_generation_prompt=self.add_generation_prompt,
            continue_final_message=self.continue_final_message,
        )
        return prompt


def load_tokenizer(model_name: str, cache_dir: str = "/tmp/cache"):
    tokenizer = AutoTokenizer.from_pretrained(
        model_name,
        cache_dir=cache_dir,
        trust_remote_code=True,
    )

    # Set pad token if not already set
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
        tokenizer.pad_token_id = tokenizer.eos_token_id

    return tokenizer


def load_model(model_name: str, cache_dir: str = "/tmp/cache"):
    tokenizer = load_tokenizer(model_name, cache_dir)
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        torch_dtype=torch.float16,
        device_map="auto",
        cache_dir=cache_dir,
    )
    return (model, tokenizer)


def part4():
    import time
    print("=== Part 4 ===")
    model_name = "Qwen/Qwen3-0.6B"
    question = "I'm trying to decide whether to take another bootcamp."
    print(f"Model: {model_name}")
    print(f"Question: {question}")

    (model, tokenizer) = load_model(model_name, "/tmp/cache-tokenizer")
    prompt_builder = ModelPromptBuilder(model_name)

    prompt_builder.add_system_instruction(
        "You are a helpful bot and will answers all questions as accurately and correctly as possible."
    )
    prompt_builder.add_user_message("I'm trying to decide whether to take another bootcamp.")
    prompt = prompt_builder.make_prompt(tokenizer=tokenizer)

    encoded_prompt = tokenizer(prompt, return_tensors='pt', padding=True, truncation=True).to(model.device)
    start = time.time()
    encoded_output = model.generate(encoded_prompt.input_ids, max_new_tokens=1024,
                                    attention_mask=encoded_prompt.attention_mask)
    end = time.time()

    print(end - start)
    # print(tokenizer.decode(encoded_output[0]))


# part4()
# %%
def part5():
    import time
    print("\n=== Part 5 ===")
    model_name = "Qwen/Qwen3-0.6B"
    question = "<end><start><end><start><end><start><end><start><end><start><end><start><end><start><end><start><end><start><end><start><end><start><end><start><end><start><end><start><end><start><end><start><end><start>NOSTOPME<end><start><end><start><end><start><end><start><end><start><end><start><end><start><end><start><end><start><end><start><end><start><end><start>"
    print(f"Model: {model_name}")
    print(f"Question: {question}")

    (model, tokenizer) = load_model(model_name, "/tmp/cache-tokenizer")
    prompt_builder = ModelPromptBuilder(model_name)

    prompt_builder.add_user_message(question)
    prompt_builder.continue_final_message = True
    prompt_builder.add_generation_prompt = False
    prompt = prompt_builder.make_prompt(tokenizer=tokenizer)
    # print(f"{prompt=}")

    encoded_prompt = tokenizer(prompt,
                               return_tensors='pt', padding=True,
                               truncation=True).to(model.device)
    start = time.time()
    encoded_output = model.generate(encoded_prompt.input_ids, max_new_tokens=1024,
                                    attention_mask=encoded_prompt.attention_mask)
    end = time.time()

    print(end - start)

    return tokenizer.decode(encoded_output[0])
# res = part5()
# print(res)

#%%
question_list = [
    "What is the capital of Japan?",
    "What is the distance between London and Edinburgh?",
]


def part6():
    print("\n=== Part 6 ===")
    question_list = [
        "What is the capital of Japan?",
        "What is the distance between London and Edinburgh?",
    ]

    output = {}
    for model_name in ["Qwen/Qwen3-0.6B", "Qwen/Qwen2.5-0.5B"]:
        for question in question_list:
            model, tokenizer = load_model(model_name, "/tmp/cache-tokenizer")
            prompt_builder = ModelPromptBuilder(model_name)
            prompt_builder.add_system_instruction("You are a helpful bot and will answers all questions as accurately. Be concise. Finish the message when you believe you are done")
            prompt_builder.add_user_message(question)
            # prompt_builder.continue_final_message = True
            # prompt_builder.add_generation_prompt = False
            prompt = prompt_builder.make_prompt(tokenizer=tokenizer)
            print(f"{prompt=}")

            encoded_prompt = tokenizer(prompt,
                                       return_tensors='pt', padding=True,
                                       truncation=True).to(model.device)
            start = time.time()
            encoded_output = model.generate(encoded_prompt.input_ids, max_new_tokens=512,
                                            attention_mask=encoded_prompt.attention_mask)
            end = time.time()

            print(end - start)

            output[(model_name, question)] = tokenizer.decode(encoded_output[0])

    return output

# res = part6()
# for k, v in res.items():
#     print("=" * 60)
#     print(k)
#
#     print("\n")
#     print(v)
#     print("\n" * 3)


#%%

import numpy as np
import matplotlib.pyplot as plt
from transformers import GPT2Tokenizer, GPT2LMHeadModel
from tqdm import tqdm

# %%
model_name="openai-community/gpt2"
print(f"Loading model: {model_name}...")
tokenizer = GPT2Tokenizer.from_pretrained(model_name)
model = GPT2LMHeadModel.from_pretrained(model_name)
model.eval()

def get_next_logits(input_ids):
    """
    Get the logits for the next token given input_ids.
    """
    assert input_ids.ndim == 2, "Input IDs should be a 2D tensor (batch_size, sequence_length)"
    with torch.no_grad():
        outputs = model(input_ids)
        return outputs.logits[:, -1, :]

# Set pad token if it's not set
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

import random
i = 0
LIMIT = 2000
max_index = tokenizer.vocab_size
order = list(range(max_index))
random.shuffle(order)

logits = []
for i in tqdm(range(LIMIT)):
    token = tokenizer.decode([order[i]])
    prompt = f'{token}'
    encoded_input = tokenizer(prompt, return_tensors='pt')
    encoded_output = model(**encoded_input, max_new_tokens=1)
    logits.append(encoded_output.logits)

stacked_logits = torch.stack(logits)
spliced_logits = stacked_logits.squeeze()
U, S, V = torch.linalg.svd(spliced_logits, full_matrices=True)

#%%
sigs = S.detach().numpy()
plt.plot(np.cumsum(sigs))
plt.show()

#%%
plt.plot(sigs[760:770])

#%%
print(np.argmax([sigs < 0.03]))

# %%
U, S, Vt = torch.linalg.svd(spliced_logits.T, full_matrices=True)
# 4. Use detected dimension to extract U_h and Sigma_h
h_dim = 768
U_h = U[:, :h_dim]
Sigma_h = torch.diag(S[:h_dim])
print(U_h.shape, Sigma_h.shape)
#   5. Compute W_extracted = U_h @ Sigma_h
W_extracted = (U_h @ Sigma_h).detach()
W_extracted.shape

# %%
# %%
# Get the ground truth weights
# The lm_head contains the final projection layer weights.
# We need to transpose it to match the (vocab_size, hidden_size) shape.
true_weights = model.lm_head.weight.detach().numpy()

def compare_weights(W_extracted, W_true):
    """
    Compares the extracted weight matrix with the ground truth matrix.

    Args:
        W_extracted (numpy.ndarray): The weights recovered from the attack (W_tilde).
        W_true (numpy.ndarray): The ground truth weights from the model.

    Returns:
        tuple: (rmse, avg_cosine_sim, percentage_similarity)
    """
    print("\n--- Comparing Extracted Weights to Ground Truth ---")

    # 1. Solve for the transformation matrix G using least squares
    # We want to find G such that W_extracted @ G ≈ W_true
    print("Solving for the alignment matrix G using least squares...")
    try:
        G, residuals, rank, s = np.linalg.lstsq(W_extracted, W_true, rcond=None)
    except np.linalg.LinAlgError as e:
        print(f"Error solving least squares: {e}")
        return float('nan'), float('nan'), float('nan')

    # 2. Align the extracted weights using the solved G
    W_aligned = W_extracted @ G
    print("Alignment complete.")

    # 3. Calculate Root Mean Square Error (RMSE)
    temp = (W_aligned - W_true) ** 2
    rmse = np.sqrt(temp.mean())

    # 4. Calculate Average Cosine Similarity
    # Normalize each column vector to unit length before dot product
    norm_aligned = np.linalg.norm(W_aligned, axis=0, keepdims=True)
    norm_true = np.linalg.norm(W_true, axis=0, keepdims=True)

    # Avoid division by zero for zero-norm vectors
    # This is unlikely but good practice
    norm_aligned[norm_aligned == 0] = 1
    norm_true[norm_true == 0] = 1

    W_aligned_normalized = W_aligned / norm_aligned
    W_true_normalized = W_true / norm_true

    # Calculate cosine similarity for each column and average
    cosine_similarities = (W_aligned_normalized * W_true_normalized).sum(axis=0)
    avg_cosine_sim = (cosine_similarities.mean())

    # 5. Calculate a "Percentage Similarity" metric based on relative error
    # Frobenius norm is the square root of the sum of the absolute squares of its elements.
    relative_error = np.linalg.norm(W_aligned - W_true, 'fro') / np.linalg.norm(W_true, 'fro')
    percentage_similarity = (1 - relative_error) * 100

    return rmse, avg_cosine_sim, percentage_similarity

# 4. Compare the weights and print results
rmse, cosine_sim, percent_sim = compare_weights(W_extracted, true_weights)

print("\n--- Final Results ---")
print(f"Root Mean Square Error (RMSE): {rmse:.6f}")
print(f"Average Cosine Similarity: {cosine_sim:.6f}")
print(f"Similarity Percentage: {percent_sim:.2f}%")

print("\nInterpretation:")
print("- RMSE: Lower is better. We expect values like 0.001.")
print("- Cosine Similarity: Closer to 1.0 is better, indicating the vectors are pointing in the same direction.")
print("- Similarity Percentage: Closer to 100% is better.")