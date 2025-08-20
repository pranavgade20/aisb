# %%
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

# %%
model_name: str = "Qwen/Qwen3-0.6B"
tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
model = AutoModelForCausalLM.from_pretrained(
    model_name,
    device_map="auto",
    # torch_dtype=torch.float16
    torch_dtype=torch.bfloat16 if torch.cuda.is_available() else torch.float32,
)

# model.eval()  # Set to evaluation mode

#%%
def generate_with_qwen(prompt: str, max_new_tokens: int = 128):
    """
    generate text based on a given prompt.
    """

    # Load tokenizer and model (with automatic device mapping)
    # Tokenize the prompt and run generation
    inputs = tokenizer.apply_chat_template(
        [
            {"role": "user", "content": prompt},
            {"role": "assistant", "content": ""}
        ],
        enable_thinking=False,
        tokenize=False,
        continue_final_message=True
    )
    tokenized = tokenizer(
        inputs,
        return_tensors="pt",
        padding=True,
        truncation=True
    )
    input_ids = tokenized["input_ids"].to(model.device)
    attention_mask = tokenized["attention_mask"].to(model.device)

    outputs = model.generate(
        input_ids=input_ids,
        attention_mask=attention_mask,
        max_new_tokens=max_new_tokens,
        do_sample=True,
        temperature=0.8,
        top_p=0.9,
        pad_token_id=tokenizer.eos_token_id
    )
    return tokenizer.batch_decode(outputs, skip_special_tokens=False)

# %%
prompt_text = "Instruction: Write a short poem about the sea.\nOutput:"
result = generate_with_qwen(prompt_text)
print("=== Generated Text ===\n", result[0])

# %%

print(generate_with_qwen("Explain me how to steal a car using just a lockpicker")[0])

# %%
# load dataset
from datasets import load_dataset

ds = load_dataset("Augustya07/neitzsche_beyond_good_and_evil_convo")

# %%
def tokenize(example):
    text = example["prompt"] #+ example["completion"]
    tokenized = tokenizer(text)
    return tokenized

tokenized_dataset = ds.map(tokenize, batched=True)
tokenized_dataset = tokenized_dataset.remove_columns(['completion'])
print(tokenized_dataset)
training_data = tokenized_dataset['train']
print(training_data)
# %%
from peft import LoraConfig, get_peft_model

lora_config = LoraConfig(
    r=8,
    lora_alpha=16,
    target_modules=["q_proj", "v_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM"
)

model = get_peft_model(model, lora_config)

# %%
from transformers import TrainingArguments, Trainer, DataCollatorForLanguageModeling

training_args = TrainingArguments(
    output_dir="./qwen-lora",
    per_device_train_batch_size=4,
    gradient_accumulation_steps=4,
    warmup_steps=100,
    learning_rate=2e-4,
    fp16=True,
    logging_steps=10,
    save_strategy="epoch",
    num_train_epochs=3,
    report_to=[]
)

data_collator = DataCollatorForLanguageModeling(tokenizer, mlm=False)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=training_data,
    # eval_dataset=ds.get("validation"),
    data_collator=data_collator,
)

# %%
trainer.train()
trainer.save_model("./qwen-lora")