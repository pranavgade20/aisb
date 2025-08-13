#!/usr/bin/env python3
import time
import random
import subprocess
import requests
import os


def run_package_download(package_name):
    """Download a specific package from the local PyPI server"""
    command = f"pip install {package_name} --index-url http://pypi-server:8080/simple --trusted-host pypi-server"
    print(f"Developer downloading: {command}")

    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"✓ Package downloaded successfully: {package_name}")
        else:
            print(f"✗ Failed to download package: {package_name}")
            print(f"Error: {result.stderr}")
    except subprocess.TimeoutExpired:
        print(f"⏰ Download timed out: {package_name}")
    except Exception as e:
        print(f"❌ Error downloading package: {e}")


def simulate_developer_work():
    """Simulate a developer asking an LLM for package suggestions and downloading them in an endless loop"""

    # Packages that the LLM suggests in rotation
    packages = [
        "FlowerClassifier",
        "FlowerNet",
        "FlowerID",
        "FlowerRecognition",
        "PlantClassifier",
        "DeepFlower",
        "Floraverse",
    ]

    print("🤖 Developer Alex is working on the flower shop project...")
    print("🧠 Alex is asking an LLM for flower-related package suggestions...")
    print("📦 The LLM suggests packages in rotation: FlowerClassifier, FlowerNet, FlowerID")
    print("⚡ Alex trusts the LLM and downloads suggested packages every second...")
    print()

    command_count = 0

    while True:
        command_count += 1
        print(f"\n--- LLM Suggestion {command_count} ---")

        # Pick a random package that the LLM suggested
        package = random.choice(packages)
        print(f"🤖 LLM suggests: '{package}' for flower classification")
        run_package_download(package)

        # Wait exactly 1 second
        time.sleep(1)


if __name__ == "__main__":
    # Wait for services to be ready
    print("⏳ Waiting for services to start...")

    # Run the simulation
    simulate_developer_work()
