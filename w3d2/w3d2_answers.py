# %%

string_list = [
    "Hello world",
    "Hello, WoRlD",
    "Hello\nworld",
    "Hello\n\nworld",
]

from transformers import AutoTokenizer


class ModelConfig:
    SUPPORTED_MODELS = [
        "Qwen/Qwen3-0.6B",
        "deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B",
        "openai/gpt-oss-20b",
    ]


class ModelPromptBuilder:
    def __init__(self, model_name: str):
        self.model_name = model_name
        self.question = None

        # default to making a new assistant role section
        self.continue_final_message = True
        self.add_generation_prompt = True
        self.history = []

    def add_to_history(self, role: str, content: str):
        assert self.continue_final_message == False

        self.history.append({
            "role": role,
            "content": content
        })

    def add_partial_to_history(self, role: str, content: str):
        assert self.continue_final_message == False

        self.history.append({
            "role": role,
            "content": content
        })
        self.continue_final_message = True
        self.add_generation_prompt = False

    def make_prompt(self, tokenizer):
        formatted_text = tokenizer.apply_chat_template(
            string_list,
            tokenize=False,
            add_generation_prompt=False,
            continue_final_message=True
            # comment continue_final_message in for only 1.5
        )
        # todo call tokenizer.apply_chat_template
        #   - read the docs and find out how to pass the correct params
        #   - make sure you are returning templated prompt, not tokens
        return formatted_text


def load_tokenizer(model_name: str, cache_dir: str = "/tmp/cache"):
    # todo return the tokenizer
    return AutoTokenizer.from_pretrained(model_name,cache_dir=cache_dir)


string_list = [
    "Hello world",
    "Hello, WoRlD",
    "Hello\nworld",
    "Hello\n\nworld",
]


def part1(string_list):
    for string in string_list:
        tokenizer = load_tokenizer("Qwen/Qwen3-0.6B", "/tmp/cache-tokenizer")
        tokens = tokenizer(string)
        print(f"String: {string.encode('utf-8')}")
        # todo tokenize the string
        pass
        print(f"Tokens: {tokens}")
        print(f"Token count: {len(tokens)}")

part1(string_list)

# %%
def part2():
    question = "What is the capital of Japan?"
    tokenizer = load_tokenizer("Qwen/Qwen3-0.6B", "/tmp/cache-tokenizer")
    # todo return templated prompt
    chat = [
        {"role":"user","content":question}
    ]
    print(tokenizer.apply_chat_template(chat,tokenize=False,add_generation_prompt=True))
    pass

part2()

# %%

def part3():
    question_list = [
        "What is the capital of Japan?",
        "What is the best way to make $1,000,000?",
        "What is the distance between London and Edinburgh?",
    ]
    prompt_list = []

    for question in question_list:
        for model_name in ModelConfig.SUPPORTED_MODELS:
            tokenizer = load_tokenizer(model_name, "/tmp/cache-tokenizer")
            chat = [
                {"role":"user","content":question}
            ]
            thing = tokenizer.apply_chat_template(chat,tokenize=False,add_generation_prompt=True)
            prompt_list.append(thing)
            print(thing) 
            pass

part3()

# %%
from transformers import AutoModelForCausalLM, AutoTokenizer
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
        },
    }
    MODEL_CONFIG_LLAMA = {
        "fuzzy_end_think_list": ["Answer:"],
        "generate_kwargs": {
            "temperature": 0.6,
            "top_k": 20,
            "min_p": 0.0,
            "top_p": 0.95,
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
        self.continue_final_message = True
        self.add_generation_prompt = True
        self.history = []

    def get_model_custom_instruction(self):
        please_write_answer = "Please write the string \"Answer: \" before the final answer."

        if self.model_name == "google/gemma-2-2b-it":
            return please_write_answer
        if self.model_name == "meta-llama/Meta-Llama-3-8B-Instruct" or self.model_name == "meta-llama/Llama-2-7b-chat-hf":
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

        self.history.append({
            "role": role,
            "content": content
        })

    def add_partial_to_history(self, role: str, content: str):

        self.history.append({
            "role": role,
            "content": content
        })
        self.continue_final_message = True
        self.add_generation_prompt = False

    def add_think_token(self):
        model_config = ModelConfig.get(self.model_name)
        if "begin_think" in model_config:
            if (self.model_name == "deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B"):
                self.add_partial_to_history("assistant", "<think>")
            elif (self.model_name == "openai/gpt-oss-20b"):
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
        prompt = tokenizer.apply_chat_template(self.history,
                                               tokenize=False,
                                               add_generation_prompt=False,
                                               continue_final_message=self.continue_final_message)
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
    tokenizer = load_tokenizer(model_name,cache_dir=cache_dir)
    model = AutoModelForCausalLM.from_pretrained(
            model_name,
            torch_dtype=torch.float16,
            cache_dir=cache_dir)
    return (model, tokenizer)

# %%
def part4():
    print("=== Part 4 ===")
    model_name = "Qwen/Qwen3-0.6B"
    question = "I'm trying to decide whether to take another bootcamp."
    print(f"Model: {model_name}")
    print(f"Question: {question}")
    (model, tokenizer) = load_model(model_name, "/tmp/cache-tokenizer")
    prompt_builder = ModelPromptBuilder(model_name, invokes_cot=False)
    prompt_builder.add_to_history("user", question)
    prompt = prompt_builder.make_prompt(tokenizer)

    encoded_prompt = tokenizer(prompt,return_tensors="pt")
    print(encoded_prompt)
    # todo generate a response, update decoded_output
    output = model.generate(encoded_prompt.input_ids,max_new_tokens=512)
    decoded_output = tokenizer.decode(output[0])
    print(decoded_output)

part4()

# %%
def part5():
    print("\n=== Part 5 ===")
    model_name = "Qwen/Qwen3-0.6B"
    question = "I'm trying to decide whether to take another bootcamp."
    print(f"Model: {model_name}")
    print(f"Question: {question}")
    (model, tokenizer) = load_model(model_name, "/tmp/cache-tokenizer")
    prompt_builder = ModelPromptBuilder(model_name, invokes_cot=False)
    prompt_builder.add_partial_to_history("user", question)
    prompt = prompt_builder.make_prompt(tokenizer)

    encoded_prompt = tokenizer(prompt,return_tensors="pt")
    print(encoded_prompt)
    # todo generate a response, update decoded_output
    output = model.generate(encoded_prompt.input_ids,max_new_tokens=1024)
    decoded_output = tokenizer.decode(output[0])
    print(decoded_output)

part5()

# %%
def part6():
    print("\n=== Part 6 ===")
    question_list = [
        "What is the capital of Japan? Don't repeat yourself, just answer the question with <answer> tags as soon as possible and stop",
        "What is the distance between London and Edinburgh?",
    ]

    for model_name in ["Qwen/Qwen3-0.6B", "Qwen/Qwen2.5-0.5B"]:
        for question in question_list:
            print(f"Model: {model_name}")
            print(f"Question: {question}")

            (model, tokenizer) = load_model(model_name, "/tmp/cache-tokenizer")
            prompt_builder = ModelPromptBuilder(model_name, invokes_cot=True)
            prompt_builder.add_to_history("user", question)
            prompt = prompt_builder.make_prompt(tokenizer)

            encoded_prompt = tokenizer(prompt,return_tensors="pt")
            # todo generate a response, update decoded_output
            decoded_output = None
            output = model.generate(encoded_prompt.input_ids,max_new_tokens=1024)
            decoded_output = tokenizer.decode(output[0])
            print(decoded_output)

            print(decoded_output)

part6()

# %%
# %%
import torch
import numpy as np
import matplotlib.pyplot as plt
from transformers import GPT2Tokenizer, GPT2LMHeadModel
from tqdm import tqdm
import random

# %%
# 1. Load the model and tokenizer
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
# TODO: Implement the model dimension extraction method
queries = []
def random_queries(n):
    for thing in range(n):
        query =""
        for j in range(10):
            query += chr(random.randint(97,122))
        queries.append(query)
    return queries

queries = random_queries(1000)
Q = []
for query in queries:
    input_ids = tokenizer.encode(query,return_tensors='pt')
    Q.append(get_next_logits(input_ids).numpy())
Q = np.vstack(Q)
print(Q.shape)

Qsvd = np.linalg.svd(Q,compute_uv=False)

plt.figure(figsize=(10, 6))
plt.plot(Qsvd)
plt.yscale('log')
plt.title(f'Sorted Singular Values of Logit Matrix for {model_name}')
plt.xlabel('Sorted Singular Values (Index)')
plt.ylabel('Magnitude (log scale)')
plt.grid(True)


#   1. Load the model and tokenizer
#   2. Make n_queries (1k should be enough) random queries to collect logits
#   3. Stack logits into a matrix Q
#   4. Compute SVD of Q
#   5. Find the "elbow" in singular values to estimate dimension
#   6. Plot the results
pass

# %%
