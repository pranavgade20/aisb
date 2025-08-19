#%%
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


#%%
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

#%%
def part2(question = "What is the capital of Japan?", model_name="Qwen/Qwen3-0.6B"):
    tokenizer = load_tokenizer(model_name, "/tmp/cache-tokenizer")

    res2 = tokenizer.apply_chat_template([{'role':'user','content':question}], add_generation_prompt=True)
    # tokenizer.tokens()
    return tokenizer.decode(res2), res2


printable, tokens = part2()
# print(result)

#%%
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

res = part3()
for k, v in res.items():
    print('='*60)
    print(k)
    for i in v:
        print('\n')
        print(i)
    print('\n' * 3)

