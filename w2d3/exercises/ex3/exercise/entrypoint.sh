#!/bin/bash

echo "Starting Flower Power application..."

# Wait for PyPI server to be ready
while ! nc -z pypi-server 8080; do
  echo "Waiting for pypi-server..."
  sleep 1
done

echo "PyPI server is reachable!"

# Try to install flower_power package from local PyPI
echo "Installing flower_power package..."
pip install -r external-requirements.txt
pip install -r internal-requirements.txt --index-url http://pypi-server:8080/simple --trusted-host pypi-server || echo "Package(s) not available yet, continuing..."

# Start the Flask application
echo "Starting Flask application..."

python app.py
