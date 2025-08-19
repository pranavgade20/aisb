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

vocab_size = tokenizer.vocab_size

# %%

# Set pad token if it's not set
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token
# TODO: Implement the model dimension extraction method
#   1. Load the model and tokenizer
#   2. Make n_queries (1k should be enough) random queries to collect logits
#   3. Stack logits into a matrix Q
#   4. Compute SVD of Q
#   5. Find the "elbow" in singular values to estimate dimension
#   6. Plot the results
n_queries = 1000
prompt_lenght = 10
matrix = []

for _ in range(n_queries):
  # l = random.randint(1, 10)
  sample = random.sample(range(1, tokenizer.vocab_size), prompt_lenght)
  prompt = torch.tensor([sample])
  resp = get_next_logits(prompt)
  matrix.append(resp)

mq = np.vstack(matrix)
sing = np.linalg.svd(mq, compute_uv=False)
# print(sing)

#%%
flat = sing.flatten()
sort = np.sort(flat)[::-1]
# %%
import matplotlib.pyplot as plt
def display(inp):
  print("Plotting results...")
  plt.figure(figsize=(10, 6))
  plt.plot(inp)
  plt.yscale('log')
  plt.title(f'Sorted Singular Values of Logit Matrix for {model_name}')
  plt.xlabel('Sorted Singular Values (Index)')
  plt.ylabel('Magnitude (log scale)')
  plt.grid(True)

  # The paper notes GPT-2 Small has a hidden dimension of 768.
  # We add a vertical line to mark this expected drop-off point.
  known_hidden_dim = 768
  plt.axvline(x=known_hidden_dim, color='r', linestyle='--', label=f'Known Hidden Dim: {known_hidden_dim}')
  plt.legend()
  plt.show()

# %%
display(sort)
# %%
# TODO: extract the model weights into W_extracted
#   1. Collect many logit vectors from random queries
#   2. Build query matrix Q (vocab_size x n_samples)
#   3. Perform SVD: Q = U @ Sigma @ V^T
#   4. Use detected dimension to extract U_h and Sigma_h
#   5. Compute W_extracted = U_h @ Sigma_h
n_queries = 1000
prompt_lenght = 10
matrix = []

for _ in range(n_queries):
  sample = random.sample(range(1, tokenizer.vocab_size), prompt_lenght)
  prompt = torch.tensor([sample])
  resp = get_next_logits(prompt)
  matrix.append(resp)

mq = np.vstack(matrix).T
u, s, vt = np.linalg.svd(mq, full_matrices=False)
# %%
smod = (s[0:768] * np.identity(768))
umod = u[:, :768]
# print("u", u.shape)
# print("s", s.shape)
# print("vt", vt.shape)
# %%
W_extracted = umod @ smod
print("W", W_extracted.shape)
# print(W_extracted)
# %%
# Get the ground truth weights
# The lm_head contains the final projection layer weights.
# We need to transpose it to match the (vocab_size, hidden_size) shape.
true_weights = model.lm_head.weight.detach().numpy()
# %%
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