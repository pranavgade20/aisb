#%%
import numpy as np
import matplotlib.pyplot as plt
from PIL import Image

#%%
def compute_fft_magnitude(image_array):
    """Compute FFT magnitude spectrum (log scale)."""
    fft = np.fft.fft2(image_array)
    fft_shifted = np.fft.fftshift(fft)
    magnitude = 20 * np.log(np.abs(fft_shifted) + 1e-11)
    return magnitude

def show_image_and_fft(image_array, title):
    """Display image and its FFT magnitude spectrum."""
    magnitude = compute_fft_magnitude(image_array)

    plt.figure(figsize=(10, 4))
    plt.subplot(1, 2, 1)
    plt.imshow(image_array, cmap='gray')
    plt.title(f"Image: {title}")
    plt.axis('off')

    plt.subplot(1, 2, 2)
    plt.imshow(magnitude, cmap='gray')
    plt.title("FFT Magnitude Spectrum")
    plt.axis('off')
    plt.show()

# Example 1: Smooth gradient (low frequency)
gradient = np.tile(np.linspace(0, 255, 256, dtype=np.uint8), (256, 1))

# Example 2: Checkerboard (high frequency)
def create_checkerboard(size=16, num_squares=8):
    img = np.zeros((size*num_squares, size*num_squares), dtype=np.uint8)
    for y in range(num_squares):
        for x in range(num_squares):
            if (x+y) % 2 == 0:
                img[y*size:(y+1)*size, x*size:(x+1)*size] = 255
    return img

checkerboard = create_checkerboard(size=16, num_squares=8)

# Example 3: Sinusoidal wave (horizontal stripes)
x = np.linspace(0, 2*np.pi*10, 256)  # 10 cycles
sinusoid = (127.5 * (1 + np.sin(x))).astype(np.uint8)
sinusoidal_image = np.tile(sinusoid, (256, 1))

# Example 4: Random noise (all frequencies)
random_noise = np.random.randint(0, 256, (256, 256), dtype=np.uint8)

# Show all examples
show_image_and_fft(gradient, "Smooth Gradient (Low Frequency)")
show_image_and_fft(checkerboard, "Checkerboard (High Frequency)")
show_image_and_fft(sinusoidal_image, "Horizontal Sinusoid (Striped Pattern)")
show_image_and_fft(random_noise, "Random Noise (All Frequencies)")
