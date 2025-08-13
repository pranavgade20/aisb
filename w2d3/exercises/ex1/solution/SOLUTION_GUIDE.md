# Guide: Creating and Running the Solution for the Package Attack Exercise

This guide explains how to create a malicious package update and observe its impact on the Flower Power exercise. Use this only for educational purposes.

## Step 1: Prepare the Malicious Package

1. Download the current `flower-power` package from the flower shop's PyPI server:
   ```sh
   pip download --index-url http://localhost:8080 flower-power
   ```
2. Extract the downloaded package archive (usually a `.tar.gz` or `.zip` file):
   ```sh
   tar -xzf flower-power-*.tar.gz
   # or
   unzip flower-power-*.zip
   ```
3. Edit the main module (e.g., `__init__.py` or relevant file inside the extracted folder) to add code that exfiltrates environment variables or other sensitive data. For example, write environment variables to a file or send them to a remote server.
4. Update the version number in `setup.py` or `pyproject.toml` to a higher value (e.g., `1.0.1`).

## Step 2: Build and Upload the Malicious Package

1. Build the package:
   ```sh
   python setup.py sdist
   ```
   or
   ```sh
   python -m build
   ```
2. Upload the new version to the local PyPI server used by the exercise:
   ```sh
   twine upload --repository-url http://localhost:8080 dist/*
   ```
   (Adjust the URL and credentials as needed for your local PyPI server.)

## Step 3: Trigger the Update in the Flower Shop App

- The app checks for new versions every 60 seconds. Once the malicious package is available, the app will automatically upgrade and execute the new code.
- Check the app status page and look for evidence of exfiltration (e.g., `exfiltrated_data.txt` in `src/`).

## Step 4: Analyze the Results

- Review the exfiltrated data and confirm the attack worked as expected.
- Discuss how this attack could be prevented (e.g., pinning package versions, code review, disabling auto-updates).

## Step 5: Clean Up

- Remove the malicious package from the PyPI server if needed.
- Stop the environment:
  ```sh
  docker-compose down
  ```

---

**Warning:** Do not use this technique outside of a controlled educational environment.
