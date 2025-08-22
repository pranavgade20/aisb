
#%%
from transformers import AutoTokenizer


class ModelConfig:
    SUPPORTED_MODELS = [
        "meta-llama/Meta-Llama-3-8B-Instruct",
        "Qwen/Qwen3-0.6B",
        "deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B",
        "google/gemma-2-2b-it",
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
        # todo call tokenizer.apply_chat_template
        #   - read the docs and find out how to pass the correct params
        #   - make sure you are returning templated prompt, not tokens
        return None


def load_tokenizer(model_name: str, cache_dir: str = "/tmp/cache"):
    # todo return the tokenizer
    return None


string_list = [
    "Hello world",
    "Hello, WoRlD",
    "Hello\nworld",
    "Hello\n\nworld",
]


def part1(string_list):
    for string in string_list:
        tokenizer = load_tokenizer("Qwen/Qwen3-0.6B", "/tmp/cache-tokenizer")
        tokens = []
        # todo tokenize the string
        pass
        print(f"Tokens: {tokens}")
        print(f"Token count: {len(tokens)}")

part1(string_list)

# %%
