FROM python:3.10-bookworm

# Install some packages that will be useful in the future
RUN apt-get update && apt-get install -y ca-certificates iptables libnetfilter-queue-dev libcap2-bin sudo && rm -rf /var/lib/apt/lists/*

# UNCOMMENT THE LINES BELOW IN EXERCISE 5.3
# # Copy our mitmproxy CA certificate
# COPY mitmproxy-certs/mitmproxy-ca-cert.cer /usr/local/share/ca-certificates/mitmproxy-ca.crt
# # Update the certificate store
# RUN update-ca-certificates
# # Set Python to use system certificates
# ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
# ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

RUN pip install --no-cache-dir requests scapy mitmproxy netfilterqueue dnspython

RUN useradd -m -u 1000 myuser && \
    echo "myuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set capabilities on python binary (allows non-root netfilter access)
RUN setcap cap_net_admin,cap_net_raw+eip $(readlink -f $(which python3))
# Copy your scripts
WORKDIR /app
COPY --chown=myuser:myuser . /app


# Switch to non-root user
USER myuser
# Command to run the application
# CHANGE THE COMMAND BELOW IN EXERCISE 7.1
CMD ["python", "w1d2_answers_agent.py"]
# CMD ["bash", "start-agent.sh"]
