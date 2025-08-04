FROM mcr.microsoft.com/devcontainers/python:1-3.12-bullseye

# Copy requirements.txt first for better layer caching
COPY requirements.txt /tmp/requirements.txt

# Install Python dependencies
RUN pip3 install --user -r /tmp/requirements.txt
