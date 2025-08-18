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
