# Solution Guide: Local PyPI Server with Malicious Package

## Overview

This solution sets up a local PyPI server using Docker and pypiserver, serving custom Python packages from the `packages/` directory. It demonstrates how a malicious package can be distributed via a private PyPI server.

## Structure

- **docker-compose.yml**: Defines a service `pypi.local` that builds from `Dockerfile.pypi`, exposes port 8081, and mounts the `packages/` directory.
- **Dockerfile.pypi**: Builds a Python 3.9 slim image, installs `pypiserver` with authentication support, and runs the server on port 8080 serving `/packages`.
- **packages/**: Contains source distributions (`.tar.gz`) of the `flower_power` package.
- **malicious-package/**: Source code for the `flower_power` package, version 3.0.2, which contains a malicious payload in its `main()` function.

## How It Works

1. **Build and Run the Server**
   - Run `docker-compose up --build` in the solution directory.
   - The PyPI server will be available at `http://localhost:8081`.

2. **Malicious Package**
   - The `flower_power` package is defined in [`malicious-package/flower_power/__init__.py`](malicious-package/flower_power/__init__.py).
   - Its `main()` function prints a message and returns a string indicating compromise.

3. **Distribution**
   - The built package files (`flower_power-1.0.0.tar.gz`, `flower_power-3.0.2.tar.gz`) are placed in `packages/`.
   - These can be installed using pip with the `--index-url` pointing to the local server.

## Example Usage

To install the malicious package from the local PyPI server:

```sh
pip install flower_power --index-url http://localhost:8081/simple
```

## Docker Networking Note

Ensure that any Docker containers or services that need to access the local PyPI server are on the same Docker network. You can specify a custom network in your `docker-compose.yml` or use the default network created by Docker Compose. This allows containers to communicate with each other using service names (e.g., `pypi.local`) or the correct IP address.

## Security Note

This setup demonstrates how a malicious package can be distributed via a private PyPI server. Always verify the source and contents of packages before