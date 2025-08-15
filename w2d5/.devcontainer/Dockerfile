FROM mcr.microsoft.com/devcontainers/python:1-3.12-bullseye

# Copy requirements.txt first for better layer caching
COPY requirements.txt /tmp/requirements.txt

# Install Python dependencies
RUN pip3 install --user -r /tmp/requirements.txt

# Install gcloud CLI, terraform, and direnv
RUN apt-get update -y

RUN apt-get install -y \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release \
    curl 

RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
    && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - \
    && wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/hashicorp.list

RUN apt-get update -y

RUN apt-get install -y google-cloud-cli terraform direnv

RUN apt-get install -y vim

RUN apt-get clean \
    && rm -rf /var/lib/apt/lists/*
