import numpy as np
import matplotlib.pyplot as plt
import qrcode


class FourierCanvas:
    """Simplified canvas for noise generation, FFT manipulation, and inverse FFT."""
    
    def __init__(self, size=256):
        self.size = size
        self.image = None
        self.fft = None
    
    def generate_noise(self, noise_type='gaussian', amplitude=1.0, seed=None):
        """Generate noise in spatial domain.
        
        Args:
            noise_type: 'gaussian', 'uniform', or 'salt_pepper'
            amplitude: Noise strength
            seed: Random seed for reproducibility
        """
        if seed is not None:
            np.random.seed(seed)
            
        if noise_type == 'gaussian':
            self.image = np.random.normal(0, amplitude, (self.size, self.size))
        elif noise_type == 'uniform':
            self.image = np.random.uniform(-amplitude, amplitude, (self.size, self.size))
        elif noise_type == 'salt_pepper':
            self.image = np.random.choice([0, amplitude], (self.size, self.size))
        
        return self
    
    def compute_fft(self):
        """Compute FFT of current image."""
        if self.image is None:
            raise ValueError("No image data. Generate noise first.")
        
        self.fft = np.fft.fftshift(np.fft.fft2(self.image))
        return self
    
    def add_pattern_to_fft(self, pattern, magnitude=1000):
        """Add custom pattern to log FFT space.
        
        Args:
            pattern: 2D numpy array (binary pattern, 0s and 1s)
            magnitude: Strength of pattern frequencies
        """
        if self.fft is None:
            raise ValueError("No FFT data. Compute FFT first.")
        
        # Ensure pattern is same size as FFT, resize if needed
        if pattern.shape != (self.size, self.size):
            # Simple resize by repeating or cropping
            pattern_resized = np.zeros((self.size, self.size))
            min_h = min(pattern.shape[0], self.size)
            min_w = min(pattern.shape[1], self.size)
            
            # Center the pattern
            start_h = (self.size - min_h) // 2
            start_w = (self.size - min_w) // 2
            pattern_start_h = (pattern.shape[0] - min_h) // 2
            pattern_start_w = (pattern.shape[1] - min_w) // 2
            
            pattern_resized[start_h:start_h+min_h, start_w:start_w+min_w] = \
                pattern[pattern_start_h:pattern_start_h+min_h, pattern_start_w:pattern_start_w+min_w]
            
            pattern = pattern_resized
        
        # Work in log magnitude space
        fft_magnitude = np.abs(self.fft)
        fft_phase = np.angle(self.fft)
        
        # Convert to log space
        log_magnitude = np.log(1 + fft_magnitude)
        
        # Add pattern to log magnitude (where pattern is 1)
        log_magnitude += pattern * magnitude
        
        # Convert back from log space
        new_magnitude = np.exp(log_magnitude) - 1
        
        # Reconstruct complex FFT with new magnitude
        self.fft = new_magnitude * np.exp(1j * fft_phase)
        
        return self
    
    def inverse_fft(self):
        """Transform back to spatial domain."""
        if self.fft is None:
            raise ValueError("No FFT data.")
        
        self.image = np.real(np.fft.ifft2(np.fft.ifftshift(self.fft)))
        return self
    
    def show_all_stages(self, original_noise, original_fft, qr_pattern, save_to_file=True):
        """Display all 6 stages of the workflow as subplots."""
        fig, axes = plt.subplots(2, 3, figsize=(15, 10))
        
        # 1. Original noise in spatial domain
        ax = axes[0, 0]
        noise_display = original_noise
        if noise_display.max() != noise_display.min():
            noise_display = (noise_display - noise_display.min()) / (noise_display.max() - noise_display.min())
        ax.imshow(noise_display, cmap='gray')
        ax.set_title('1. Noise (Spatial)')
        ax.axis('off')
        
        # 2. Noise in Fourier space (magnitude)
        ax = axes[0, 1]
        fft_magnitude = np.abs(original_fft)
        ax.imshow(fft_magnitude, cmap='gray')
        ax.set_title('2. Noise (Fourier Magnitude)')
        ax.axis('off')
        
        # 3. Noise in Fourier log space
        ax = axes[0, 2]
        fft_log_magnitude = np.log(1 + np.abs(original_fft))
        ax.imshow(fft_log_magnitude, cmap='gray')
        ax.set_title('3. Noise (Fourier Log Magnitude)')
        ax.axis('off')
        
        # 4. Noise + QR in Fourier log space
        ax = axes[1, 0]
        final_fft_log = np.log(1 + np.abs(self.fft))
        ax.imshow(final_fft_log, cmap='gray')
        ax.set_title('4. Noise + QR (Fourier Log)')
        ax.axis('off')
        
        # 5. Noise + QR in Fourier space (magnitude)
        ax = axes[1, 1]
        final_fft_magnitude = np.abs(self.fft)
        ax.imshow(final_fft_magnitude, cmap='gray')
        ax.set_title('5. Noise + QR (Fourier Magnitude)')
        ax.axis('off')
        
        # 6. Final result in spatial domain
        ax = axes[1, 2]
        final_display = self.image
        if final_display.max() != final_display.min():
            final_display = (final_display - final_display.min()) / (final_display.max() - final_display.min())
        ax.imshow(final_display, cmap='gray')
        ax.set_title('6. Final Result (Spatial)')
        ax.axis('off')
        
        plt.tight_layout()
        
        if save_to_file:
            filename = 'fourier_workflow_all_stages.png'
            plt.savefig(filename, dpi=150, bbox_inches='tight')
            print(f"Image saved as: {filename}")
        else:
            plt.show()


def generate_qr_pattern(text, size=256):
    """Generate QR code pattern as binary numpy array.
    
    Args:
        text: Text to encode
        size: Target size for the pattern
        
    Returns:
        Binary numpy array (0s and 1s) scaled to target size
    """
    try:
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=1,
            border=1,
        )
        qr.add_data(text)
        qr.make(fit=True)
        
        # Convert to numpy array
        qr_img = qr.make_image(fill_color="black", back_color="white")
        pattern = np.array(qr_img, dtype=float)
        
        # Convert to binary (1 for black QR pixels, 0 for white)
        pattern = (pattern < 128).astype(float)
        
        # Scale to target size using simple nearest neighbor interpolation
        original_size = pattern.shape[0]
        scaled_pattern = np.zeros((size, size))
        
        for i in range(size):
            for j in range(size):
                # Map scaled coordinates back to original coordinates
                orig_i = int(i * original_size / size)
                orig_j = int(j * original_size / size)
                # Ensure we don't go out of bounds
                orig_i = min(orig_i, original_size - 1)
                orig_j = min(orig_j, original_size - 1)
                scaled_pattern[i, j] = pattern[orig_i, orig_j]
        
        return scaled_pattern
        
    except ImportError:
        print("qrcode or scipy library not available. Creating checkerboard pattern instead.")
        # Fallback: create a simple checkerboard pattern scaled to size
        pattern = np.zeros((size, size))
        for i in range(size):
            for j in range(size):
                pattern[i, j] = ((i // 10) + (j // 10)) % 2
        return pattern


if __name__ == "__main__":
    # Generate QR code pattern
    qr_pattern = generate_qr_pattern("samova.net")
    
    # Create canvas and demonstrate workflow
    canvas = FourierCanvas(size=256)
    
    # 1. Generate noise
    canvas.generate_noise(noise_type='gaussian', amplitude=0.1, seed=42)
    original_noise = canvas.image.copy()
    
    # 2. Compute FFT
    canvas.compute_fft()
    original_fft = canvas.fft.copy()
    
    # 3. Add custom QR pattern to log FFT space
    canvas.add_pattern_to_fft(qr_pattern, magnitude=2.0)
    
    # 4. Transform back to spatial domain
    canvas.inverse_fft()
    
    # Display all stages
    canvas.show_all_stages(original_noise, original_fft, qr_pattern)
    
    print("Workflow complete:")
    print("1. Generated gaussian noise")
    print("2. Computed FFT")
    print("3. Added QR code pattern to log FFT space")
    print("4. Transformed back to spatial domain")
    print("Result: QR code pattern should be visible in the spatial image!")