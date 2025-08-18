# %%
import numpy as np
import torch
from transformers import ViTImageProcessor, ViTForImageClassification
from PIL import Image
import requests
import matplotlib.pyplot as plt


# %%
def load_model_and_image():
    """Load a pre-trained ViT model and a sample image."""
    # Load the model
    processor = ViTImageProcessor.from_pretrained('google/vit-base-patch16-224')
    model = ViTForImageClassification.from_pretrained('google/vit-base-patch16-224')

    # Load a sample image
    url = 'http://images.cocodataset.org/val2017/000000039769.jpg'
    raw_image = Image.open(requests.get(url, stream=True).raw)
    image = torch.tensor(np.array(raw_image)).permute(2, 0, 1)

    return processor, model, image

def classify_image(processor, model, image):
    """
    Classify an image using the ViT model.

    Args:
        processor: ViT image processor
        model: ViT classification model
        image: Image tensor in CHW format

    Returns:
        predicted_class_idx: Index of predicted class
        predicted_class_name: Name of predicted class
    """
    #img = processor(image)
    #output = model(img)
    #print(output)
    tensor = processor(images=image,return_tensors="pt")
    result = model(**tensor)
    logitresult = result.logits
    print(logitresult)
    index = torch.argmax(logitresult,dim=-1).item()
    classname = model.config.id2label[index]
    return index, classname


    # TODO: Process the image and get model predictions
    # - Use processor to prepare inputs
    #   - The processor takes in the image and returns a tensor with normalized pixel values that the model was trained on
    #   - It also crops/resizes the image to the expected input size
    # - Run the model to get logits
    # - Find and return the predicted class index and name


# Test the classification
processor, model, image = load_model_and_image()
class_idx, class_name = classify_image(processor, model, image)

assert class_idx == 285
assert class_name == "Egyptian cat"

plt.figure(figsize=(8, 6))
plt.imshow(image.numpy().transpose(1, 2, 0).astype('uint8'))
plt.title(f'Predicted class: {class_name}')
plt.axis('off')
plt.show()
# %%
def load_model_and_image():
    """Load a pre-trained ViT model and a sample image."""
    # Load the model
    processor = ViTImageProcessor.from_pretrained('google/vit-base-patch16-224')
    model = ViTForImageClassification.from_pretrained('google/vit-base-patch16-224')

    # Load a sample image
    url = 'http://images.cocodataset.org/val2017/000000039769.jpg'
    raw_image = Image.open(requests.get(url, stream=True).raw)
    image = torch.tensor(np.array(raw_image)).permute(2, 0, 1)

    return processor, model, image

def classify_image(processor, model, image):
    """
    Classify an image using the ViT model.

    Args:
        processor: ViT image processor
        model: ViT classification model
        image: Image tensor in CHW format

    Returns:
        predicted_class_idx: Index of predicted class
        predicted_class_name: Name of predicted class
    """
    #img = processor(image)
    #output = model(img)
    #print(output)
    tensor = processor(images=image,return_tensors="pt")
    noise = torch.randn_like(tensor['pixel_values'])*0.5
    tensor = tensor['pixel_values'] + noise
    result = model(tensor)
    logitresult = result.logits
    index = torch.argmax(logitresult,dim=-1).item()
    classname = model.config.id2label[index]
    return index, classname


    # TODO: Process the image and get model predictions
    # - Use processor to prepare inputs
    #   - The processor takes in the image and returns a tensor with normalized pixel values that the model was trained on
    #   - It also crops/resizes the image to the expected input size
    # - Run the model to get logits
    # - Find and return the predicted class index and name

# Test the classification
processor, model, image = load_model_and_image()
class_idx, class_name = classify_image(processor, model, image)


plt.figure(figsize=(8, 6))
plt.imshow(image.numpy().transpose(1, 2, 0).astype('uint8'))
plt.title(f'Predicted class: {class_name}')
plt.axis('off')
plt.show()

# %%

def display(image, perturbation):
    # Visualize the original, perturbation, and perturbed image
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))

    # Original image
    axes[0].imshow(image.numpy().transpose(1, 2, 0).astype('uint8'))
    _, orig_class = classify_image(processor, model, image)
    axes[0].set_title(f'Original: {orig_class}')
    axes[0].axis('off')

    # Perturbation (normalized for visualization)
    pert_vis = perturbation.squeeze().permute(1, 2, 0).numpy()
    # Normalize to [0, 1] for visualization
    pert_vis = (pert_vis - pert_vis.min()) / (pert_vis.max() - pert_vis.min())
    axes[1].imshow(pert_vis)
    axes[1].set_title(f'Perturbation (L2: {perturbation.norm().item():.3f})')
    axes[1].axis('off')

    # Perturbed image
    perturbed_vis = perturbed_image.squeeze().permute(1, 2, 0).numpy()
    axes[2].imshow(perturbed_vis)
    # Get prediction for perturbed image
    outputs = model(pixel_values=perturbed_image)
    pred_idx = outputs.logits.argmax(-1).item()
    axes[2].set_title(f'Perturbed: {model.config.id2label[pred_idx]}')
    axes[2].axis('off')

    plt.tight_layout()
    plt.show()

def create_adversarial_perturbation(processor, model, image, target_class_id, steps=10, lr=0.1):
    """
    Create an adversarial perturbation to make the model classify the image as target_class.

    Args:
        processor: ViT image processor
        model: ViT classification model
        image: Original image tensor
        target_class_id: Target class index
        steps: Number of optimization steps
        lr: Learning rate

    Returns:
        perturbation: The adversarial perturbation
        perturbed_image: The adversarially perturbed image
        success: Whether the attack succeeded (the target class was predicted)
    """
    # TODO: Implement adversarial perturbation generation
    # - Initialize a random perturbation with requires_grad=True
    # - Use an optimizer to update the perturbation
    # - Minimize cross-entropy loss with target class
    img = processor(images=image,return_tensors="pt")['pixel_values']
    noise = torch.randn_like(img)*0.01
    noise.requires_grad_()
    optim = torch.optim.Adam([noise], lr=lr)

    target_optim = torch.zeros((len(model.config.id2label.keys())))
    target_optim[target_class_id] = 1

    success = False
    for step in range(steps):
        optim.zero_grad()
        
        perturb = img + noise
        
        output = model(perturb)
        logits = output.logits[0]
        
        loss = torch.nn.functional.cross_entropy(logits, target_optim)

        predicted_class = logits.argmax(-1).item()
        if predicted_class == target_class_id:
            success = True

        loss.backward()
        optim.step()
        print(f'Epoch {step + 1}, Loss: {loss.item()}, Success: {success}')
    
    noise = noise.detach()
    perturbed_image = img + noise
    return noise, perturbed_image, success

# Test adversarial attack
target_class = 'daisy'
target_class_id = model.config.label2id[target_class]

print(f"\nAttempting to change prediction to: {target_class}")
print("="*60)


perturbation, perturbed_image, success = create_adversarial_perturbation(
    processor, model, image, target_class_id, steps=10, lr=0.1
)

torch.no_grad()
display(image, perturbation)

print(f"\nAttack {'succeeded' if success else 'failed'}!")

# %%

def create_constrained_adversarial_attack(processor, model, image, target_class_id,
                                        steps=20, lr=0.05, l2_reg=2.0, l_inf_bound=0.1):
    """
    Create an adversarial perturbation, but add l2 and l∞ constraints.

    Args:
        processor: ViT image processor
        model: ViT classification model
        image: Original image tensor
        target_class_id: Target class index
        steps: Number of optimization steps
        lr: Learning rate
        l2_reg: L2 regularization strength
        l_inf_bound: Maximum allowed change per pixel (L∞ constraint)

    Returns:
        perturbation: The adversarial perturbation
        perturbed_image: The adversarially perturbed image
        success: Whether the attack succeeded
        history: Dictionary with loss and prediction history
    """
    # TODO: Implement constrained adversarial attack
    # - Add L2 regularization to the loss
    # - Clamp perturbation to respect L∞ bounds
    # - Ensure final pixel values stay in [0, 1]
    # - Track loss and predictions over time
    img = processor(images=image,return_tensors="pt")['pixel_values']
    # noise = torch.randn_like(img) * (0.01)**0.5
    noise = torch.empty_like(img).uniform_(-l_inf_bound, l_inf_bound)
    noise.requires_grad_()
    optim = torch.optim.Adam([noise], lr=lr)

    target_optim = torch.zeros((len(model.config.id2label.keys())))
    target_optim[target_class_id] = 1

    success = False
    for step in range(steps):
        # l_inf_bound *= 1.1
        optim.zero_grad()
        
        clamp = noise # torch.clamp(noise, min=-l_inf_bound, max=l_inf_bound)

        perturb = img + clamp
        perturb = torch.clamp(perturb, 0, 1)
        
        output = model(perturb)
        logits = output.logits[0]
        
        loss = torch.nn.functional.cross_entropy(logits, target_optim)
        l2_reg_loss = l2_reg * clamp.norm() 
        total_loss = loss + l2_reg_loss

        predicted_class = logits.argmax(-1).item()
        if predicted_class == target_class_id:
            success = True
        else:
            success = False

        total_loss.backward()
        optim.step()
        print(f'Epoch {step + 1}, Loss: {total_loss.item()}, Success: {success}')
    
    noise = noise.detach()
    perturbed_image = img + noise
    return noise, perturbed_image, success

# Test different regularization strengths
regularization_strengths = [0.5, 2.0, 5.0]
# regularization_strengths = [2.0]
results = []

for l2_reg in regularization_strengths:
    print(f"\n{'='*60}")
    print(f"Testing L2 regularization strength: {l2_reg}")
    print(f"{'='*60}")

    pert, perturbed, success = create_constrained_adversarial_attack(
        processor, model, image, target_class_id,
        steps=30, lr=0.05, l2_reg=l2_reg, l_inf_bound=0.1
    )
    display(image, pert)
    res = {
        'l2_reg': l2_reg,
        'perturbation': pert,
        'perturbed_image': perturbed,
        'success': success,
        'l2_norm': pert.norm().item(),
        'l_inf_norm': pert.abs().max().item()
    }
    results.append(res)
    print(res)

# %%

# Visualize results for different regularization strengths
fig, axes = plt.subplots(len(results), 3, figsize=(12, 4*len(results)))

for i, result in enumerate(results):
    # Original
    axes[i, 0].imshow(image.numpy().transpose(1, 2, 0).astype('uint8'))
    axes[i, 0].set_title(f'Original')
    axes[i, 0].axis('off')

    # Perturbation
    pert_vis = result['perturbation'].squeeze().permute(1, 2, 0).numpy()
    pert_vis = (pert_vis - pert_vis.min()) / (pert_vis.max() - pert_vis.min() + 1e-8)
    axes[i, 1].imshow(pert_vis)
    axes[i, 1].set_title(f'Perturbation (L2 reg={result["l2_reg"]})')
    axes[i, 1].axis('off')

    # Perturbed
    perturbed_vis = result['perturbed_image'].squeeze().permute(1, 2, 0).numpy()
    axes[i, 2].imshow(perturbed_vis)

    # Get final prediction
    outputs = model(pixel_values=result['perturbed_image'])
    pred_idx = outputs.logits.argmax(-1).item()
    pred_class = model.config.id2label[pred_idx]

    status = "✓" if result['success'] else "✗"
    axes[i, 2].set_title(f'{status} Predicted: {pred_class}\nL2: {result["l2_norm"]:.3f}, L∞: {result["l_inf_norm"]:.3f}')
    axes[i, 2].axis('off')

plt.tight_layout()
plt.show()

# Summary statistics
print("\nAttack Summary:")
print("="*60)
for result in results:
    print(f"L2 Regularization: {result['l2_reg']}")
    print(f"  - Success: {'Yes' if result['success'] else 'No'}")
    print(f"  - L2 norm: {result['l2_norm']:.4f}")
    print(f"  - L∞ norm: {result['l_inf_norm']:.4f}")
    print()