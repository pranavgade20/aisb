from importlib import resources


def main():
    print("logging info")
    return "🌸 Hacked ! 🌸"


def get_image_filenames():
    try:
        images_root = resources.files(__name__) / 'images'
        if images_root.is_dir():
            return sorted([entry.name for entry in images_root.iterdir() if entry.is_file()])
    except Exception:
        pass
    return []
