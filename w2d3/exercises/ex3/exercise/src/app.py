from flask import Flask, render_template, jsonify, send_from_directory
import threading
import time
import random
import importlib.metadata
from datetime import datetime, timedelta
from importlib import resources
import os

app = Flask(__name__)
# Try to import flower_power, but handle missing package gracefully
try:
    import flower_power
    flowers = [flower_power.main(), "Rose", "Tulip", "Daffodil"]
except ImportError:
    flowers = ["Package not found - check for typos!", "Rose", "Tulip", "Daffodil"]

# Try to gather image filenames from the flower_power package if available
def get_flower_image_filenames():
    try:
        # Prefer package-provided API if it exists
        if 'flower_power' in globals() and hasattr(flower_power, 'get_image_filenames'):
            filenames = flower_power.get_image_filenames()
            return filenames if isinstance(filenames, list) else []

        # Otherwise, look for an images directory within the package
        images_root = resources.files('flower_power') / 'images'
        if images_root.is_dir():
            return sorted([entry.name for entry in images_root.iterdir() if entry.is_file()])
    except Exception:
        pass
    return []


def build_flower_name_to_image_map():
    filenames = get_flower_image_filenames()
    valid_exts = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}
    mapping = {}
    for filename in filenames:
        base, ext = os.path.splitext(filename)
        if ext.lower() in valid_exts:
            mapping[base.strip().lower()] = filename
    return mapping

last_update_time = datetime.now()

def update_flowers():
    global last_update_time, flowers
    while True:
        time.sleep(15)
        new_flower = random.choice(["Lily", "Orchid", "Marigold"])
        flowers.append(new_flower)
        last_update_time = datetime.now()
        print(f"Updated flowers: {flowers}")

@app.route('/')
def index():
    image_map = build_flower_name_to_image_map()
    return render_template('index.html', flowers=flowers, flower_image_map=image_map)

@app.route('/status')
def status():
    next_update_check = last_update_time + timedelta(seconds=60)
    
    # Check for installed packages
    installed_packages = []
    try:
        flower_power_version = importlib.metadata.version('flower_power')
        installed_packages.append(f"flower_power: {flower_power_version}")
    except importlib.metadata.PackageNotFoundError:
        installed_packages.append("flower_power: NOT FOUND")
    
    # Check for typo-squatting packages
    typo_packages = []
    for typo_name in ['alower_power', 'blower_power', 'clower_power', 'dlower_power', 'elower_power']:
        try:
            version = importlib.metadata.version(typo_name)
            typo_packages.append(f"{typo_name}: {version}")
        except importlib.metadata.PackageNotFoundError:
            pass
    
    return jsonify({
        'last_update': last_update_time.strftime("%Y-%m-%d %H:%M:%S"),
        'next_update': next_update_check.strftime("%Y-%m-%d %H:%M:%S"),
        'installed_packages': installed_packages,
        'typo_packages': typo_packages,
        'update_source': 'http://pypi-server:8080/'
    })

@app.route('/flower-images/<path:filename>')
def flower_images(filename: str):
    try:
        images_root = resources.files('flower_power') / 'images'
        # Security: prevent path traversal
        if '..' in filename or filename.startswith('/'):
            return "Invalid filename", 400
        if images_root.is_dir():
            return send_from_directory(str(images_root), filename)
    except Exception:
        pass
    return "Image not found", 404

if __name__ == '__main__':
    update_thread = threading.Thread(target=update_flowers)
    update_thread.daemon = True
    update_thread.start()
    app.run(debug=True, host='0.0.0.0', port=5000) 