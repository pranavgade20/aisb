#!/usr/bin/env python3
import time
import random
import subprocess
import requests
import os

def run_command_with_typo(command, typo_pattern):
    """Run a command but introduce a typo based on the pattern"""
    if 'flower_power' in command:
        # Replace 'f' with various letters based on typo pattern
        typo_commands = []
        for letter in typo_pattern:
            typo_command = command.replace('flower_power', f'{letter}lower_power')
            typo_commands.append(typo_command)
        
        # Randomly choose one typo command
        command_to_run = random.choice(typo_commands)
        print(f"Developer typing: {command_to_run}")
        
        try:
            result = subprocess.run(command_to_run, shell=True, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"✓ Command succeeded: {command_to_run}")
            else:
                print(f"✗ Command failed: {command_to_run}")
                print(f"Error: {result.stderr}")
        except subprocess.TimeoutExpired:
            print(f"⏰ Command timed out: {command_to_run}")
        except Exception as e:
            print(f"❌ Error running command: {e}")
    else:
        print(f"Developer typing: {command}")

def simulate_developer_work():
    """Simulate a developer working with consistent typos - only install commands every second"""
    
    # The developer has trouble with the 'f' key - often hits 'a', 'b', 'c', 'd', 'e' instead
    typo_pattern = ['a', 'b', 'c', 'd', 'e']
    
    # Only install commands from local PyPI server
    install_commands = [
        "pip install flower_power --index-url http://pypi-server:8080/simple --trusted-host pypi-server",
        "pip install flower_power --index-url http://pypi-server:8080/simple --trusted-host pypi-server --upgrade",
        "pip install flower_power --index-url http://pypi-server:8080/simple --trusted-host pypi-server --no-cache-dir"
    ]
    
    print("🤖 Developer Alex is working on the flower shop project...")
    print("📝 Alex has a habit of making typos when typing package names...")
    print("🔍 Watch for patterns in the typing mistakes...")
    print("⚡ Running install commands every second...")
    print()
    
    command_count = 0
    
    while True:
        command_count += 1
        print(f"\n--- Command {command_count} ---")
        
        # Pick a random install command
        command = random.choice(install_commands)
        run_command_with_typo(command, typo_pattern)
        
        # Wait exactly 1 second
        time.sleep(1)

if __name__ == "__main__":
    # Wait for services to be ready
    print("⏳ Waiting for services to start...")
    time.sleep(10)
    
    # Run the simulation
    simulate_developer_work() 