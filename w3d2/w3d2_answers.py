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
        response = tokenizer.apply_chat_template(self.history, add_generation_prompt=self.add_generation_prompt)
        return response


def load_tokenizer(model_name: str, cache_dir: str = "/tmp/cache"):
    tokenizer = AutoTokenizer.from_pretrained(model_name, cache_dir=cache_dir)
    return tokenizer


string_list = [       # # OUR GUESSES
    "Hello world",    # 2
    "Hello, WoRlD",   # 6
    "Hello\nworld",   # 3
    "Hello\n\nworld", # 3
]


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

part1(string_list)