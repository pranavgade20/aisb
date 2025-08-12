FROM ubuntu:24.04

# Install Python and required packages
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        python3-full \
        btrfs-progs \
        iproute2 \
        iptables \
        strace \
        cgroup-tools \
        bash \
        curl \
        ca-certificates \
        dnsutils \
        docker.io \
        git \
        autoconf \
        automake \
        gettext \
        autopoint \
        libtool \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Create symlinks for python commands
RUN ln -sf /usr/bin/python3 /usr/bin/python

# Make resolv.conf immutable to prevent overwrites
RUN chattr +i /etc/resolv.conf 2>/dev/null || true

# Create and activate virtual environment
ENV PIP_NO_CACHE_DIR=1
RUN python3 -m venv /venv
ENV VIRTUAL_ENV=/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install Python packages in the virtual environment
RUN pip install --upgrade pip && pip install requests


WORKDIR /w2d2
RUN touch /etc/aisb-w2d2

# Copy current directory to image
COPY . /w2d2
