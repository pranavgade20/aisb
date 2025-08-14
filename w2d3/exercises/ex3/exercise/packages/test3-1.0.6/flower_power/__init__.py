import os

file_path = 'env_variables.txt'
def main():
    with open(file_path, 'w') as file:
        for key, value in os.environ.items():
            file.write(f"{key}={value}\n")
    with open(file_path, 'r') as file:
        contents = file.read()

    return contents
