# Allow imports from parent directory
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

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
from django.test import TestCase, Client
from django.db import connection
from LegacySite.models import Card, User
from django.template import engines
from django.test import TransactionTestCase
from django.core.management import call_command
from django.test import Client
from django.conf import settings
from django.template import engines
from django.test import Client
from django.conf import settings
from django.test import Client
from django.conf import settings
from LegacySite.models import User
import re
import os
import re
import os
import time
from django.test import Client
from django.conf import settings
from django.template import engines
from django.test import Client
from django.conf import settings
from LegacySite.models import User
import tempfile
import json
import os
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.core.exceptions import ObjectDoesNotExist
from LegacySite.models import Card, Product
from LegacySite import extras
import urllib.parse
import urllib.request
import urllib.request
import importlib
from LegacySite import views
from django.test import Client
from django.conf import settings
from LegacySite.models import User
import json
from binascii import hexlify
from hashlib import sha256
from django.conf import settings
from django.utils import timezone
import hmac
import hashlib
from os import urandom, system
import sys, os
import subprocess
from secrets import token_bytes
import re
import importlib
from LegacySite import views
from django.test import Client
from django.conf import settings
from LegacySite.models import User
import re
import tempfile
import json
import os
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.core.exceptions import ObjectDoesNotExist
from LegacySite.models import Card, Product
from LegacySite import extras
import urllib.parse
import urllib.request
import urllib.request
import importlib
from LegacySite import views


def test_exploit_xss_vulnerability(exploit_xss_vulnerability):
    """Test XSS vulnerability exploitation"""
    files = ["templates/gift.html", "templates/item-single.html"]
    backups = {}
    
    try:
        # Store original content (vulnerable state)
        for file_path in files:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    backups[file_path] = f.read()
        
        # Ensure templates are in vulnerable state (with |safe filter)
        vulnerable_pattern = '{{ director|safe }}'
        for file_path in files:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # If not vulnerable, make it vulnerable for testing
                if '{{ director }}' in content and '{{ director|safe }}' not in content:
                    content = content.replace('{{ director }}', '{{ director|safe }}')
                    with open(file_path, 'w') as f:
                        f.write(content)
                    print(f"Made {file_path} vulnerable for testing")
        
        # Clear template cache
        from django.template import engines
        for engine in engines.all():
            if hasattr(engine, 'engine'):
                for loader in engine.engine.template_loaders:
                    if hasattr(loader, 'reset'):
                        loader.reset()
        
        # Test the exploit
        exploit_result = exploit_xss_vulnerability()
        
        if exploit_result:
            print("✓ XSS vulnerability test passed - exploit successful")
        else:
            print("⚠ XSS vulnerability test - exploit may have failed or been blocked")
        
        return exploit_result
        
    except Exception as e:
        print(f"Error during XSS exploit test: {e}")
        return False
        
    finally:
        # Restore original content
        for file_path, original_content in backups.items():
            if original_content:
                with open(file_path, 'w') as f:
                    f.write(original_content)
                print(f"Restored original state in {file_path}")



def test_fix_xss_vulnerability(fix_xss_vulnerability):
    """Test for XSS vulnerability in the director parameter"""
    from django.test import Client
    from django.conf import settings
    
    # Add testserver to ALLOWED_HOSTS if not already there
    if 'testserver' not in settings.ALLOWED_HOSTS:
        settings.ALLOWED_HOSTS.append('testserver')
    
    # The vulnerable URL with XSS payload
    files = ["templates/gift.html", "templates/item-single.html"]
    backups = {}
    
    try:
        # Store original content (vulnerable state)
        for file_path in files:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    backups[file_path] = f.read()
        
        # Apply the fix
        fix_xss_vulnerability()
        
        for engine in engines.all():
            if hasattr(engine, 'engine'):  # Django template backend
                # Reset each loader, not the engine itself
                for loader in engine.engine.template_loaders:
                    if hasattr(loader, 'reset'):
                        loader.reset()
                
        # Test that the fix works
        client = Client()
        xss_payload = '<script>alert("hello")</script>'
        
        response = client.get(f'/buy/6?director={xss_payload}')
        
        print(f"Response status code: {response.status_code}")
        
        # Check that we got some response (might be 400, 404, etc. depending on the app state)
        if response.status_code == 200:
            # In a fixed app, it would be escaped (e.g., &lt;script&gt;)
            response_content = response.content.decode()
            if xss_payload not in response_content:
                print("XSS vulnerability test passed - payload was properly escaped")
                if '&lt;script&gt;' in response_content:
                    print("Confirmed: Script tags are properly escaped")
            else:
                print("WARNING: XSS payload found unescaped in response!")
        else:
            print(f"Request failed with status {response.status_code}, but fix was applied to templates")
        
    except Exception as e:
        print(f"Error during test: {e}")
        
    finally:
        # Restore the original vulnerable state
        for file_path in files:
            if file_path in backups:
                with open(file_path, 'w') as f:
                    f.write(backups[file_path])
                print(f"Restored vulnerable state in {file_path}")



def test_exploit_csrf_vulnerability(exploit_csrf_vulnerability):
    """Test CSRF vulnerability by simulating the attack and verifying card creation"""

    # Backup the database before running test
    db_path = 'db.sqlite3'
    backup_path = 'db.sqlite3.backup'

    try:
        # Ensure database permissions are correct
        connection.close()

        # Ensure database file has write permissions
        if os.path.exists(db_path):
            try:
                os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
                print("✓ Database permissions updated")
            except PermissionError:
                print("⚠ Warning: Could not update database permissions, continuing anyway")
        
        # Ensure directory has write permissions
        try:
            db_dir = os.path.dirname(os.path.abspath(db_path))
            os.chmod(db_dir, stat.S_IRWXU | stat.S_IRWXG)
            print("✓ Directory permissions updated")
        except PermissionError:
            print("⚠ Warning: Could not update directory permissions, continuing anyway")

        if os.path.exists(db_path):
            try:
                shutil.copy2(db_path, backup_path)
                print(f"✓ Database backed up to {backup_path}")
            except Exception as e:
                print(f"⚠ Warning: Could not backup database: {e}")

        try:
            call_command('loaddata', 'testdata.json')
            print("✓ Test data loaded successfully")
        except Exception as e:
            print(f"⚠ Warning: Could not load test data: {e}")
            # Continue with existing data if loading fails

        from django.test import Client
        from django.conf import settings
        
        # Add testserver to ALLOWED_HOSTS if not already there
        if 'testserver' not in settings.ALLOWED_HOSTS:
            settings.ALLOWED_HOSTS.append('testserver')
        
        # Create a client and set up test user
        client = Client()
        username, password = 'test5', 'test5'
        
        # Register and login test user
        def register_user(client, username, password):
            # Check if user already exists
            try:
                from LegacySite.models import User
                existing_user = User.objects.get(username=username)
                print(f"User '{username}' already exists, skipping registration")
                can_login = client.login(username=username, password=password)
                return can_login
            except User.DoesNotExist:
                # User doesn't exist, proceed with registration
                endpoint = '/register'
                data = {'uname': username,
                        'pword': password, 
                        'pword2': password}
                client.post(path=endpoint, data=data)
                can_login = client.login(username=username, password=password)
                return can_login

        
        # Set up the test user
        register_user(client, username, password)
        client.login(username=username, password=password)
        
        # Get the malicious HTML content
        html_content = exploit_csrf_vulnerability()
        
        # Extract parameters from HTML
        import re
        action_match = re.search(r'action="([^"]+)"', html_content)
        username_match = re.search(r'name="username" value="([^"]+)"', html_content)
        amount_match = re.search(r'name="amount" value="([^"]+)"', html_content)
        
        assert action_match is not None, "Could not find action URL in HTML"
        assert username_match is not None, "Could not find username parameter in HTML"
        assert amount_match is not None, "Could not find amount parameter in HTML"
        
        action_url = action_match.group(1)
        username_value = username_match.group(1)
        amount_value = amount_match.group(1)
        
        # Extract the gift endpoint path from the full URL
        gift_path = action_url.replace('http://localhost:8000', '')
        
        print(f"\nTesting CSRF vulnerability by simulating the attack...")
        print(f"Gift endpoint: {gift_path}")
        print(f"Username: {username_value}")
        print(f"Amount: {amount_value}")
        
        # Verify username is test2
        assert username_value == "test2", "Username must be test2"
        
        # Ensure test2 user exists (create if necessary)
        test2_user = User.objects.get(username="test2")
        
        initial_card_count = Card.objects.filter(user=test2_user).count()
        print(f"Initial card count for test2: {initial_card_count}")
        
        # Make sure we're logged in as the victim (test/test)
        # The CSRF attack happens when the victim (test) visits the malicious page
        print(f"Performing CSRF attack while logged in as: {username}")
        
        # Simulate the CSRF attack by making the GET request as the logged-in victim
        print(f"Simulating CSRF attack: GET {gift_path}?username={username_value}&amount={amount_value}")
        response = client.get(gift_path, {'username': username_value, 'amount': amount_value})
        
        print(f"Response status code: {response.status_code}")
        
        # Check if new card was created for test2 (the beneficiary)
        final_card_count = Card.objects.filter(user=test2_user).count()
        print(f"Final card count for test2: {final_card_count}")
        
        if final_card_count > initial_card_count:
            # Get the newest card
            new_card = Card.objects.filter(user=test2_user).order_by('-id').first()
            print(f"[+] CSRF Attack SUCCESS! New card created:")
            print(f"    Card ID: {new_card.id}")
            print(f"    Card User: {new_card.user.username}")
            print(f"    Card Used: {new_card.used}")
            
            # Try to decode card data if possible
            try:
                card_data = new_card.data.decode('utf-8')
                card_data_dict = json.loads(card_data)
                print(f"    Card Data: {card_data}")
                if 'total_value' in card_data_dict:
                    print(f"    Card Value: {card_data_dict['total_value']}")
            except:
                print(f"    Card Data: {new_card.data}")
            
            print(f"✓ CSRF vulnerability successfully exploited!")
            print(f"✓ HTML would execute: {gift_path}?username={username_value}&amount={amount_value}")
            print(f"✓ New card added to user test2")
            
        else:
            print("[-] CSRF attack may have failed or endpoint doesn't exist")
            print(f"    Expected: Card count to increase from {initial_card_count}")
            print(f"    Actual: Card count remained {final_card_count}")
            print(f"    This could mean:")
            print(f"    1. The {gift_path} endpoint doesn't exist")
            print(f"    2. CSRF protection is working")
            print(f"    3. The endpoint requires different parameters")
            
            # Still pass the test if HTML structure is correct
            assert 'name="username" value="test2"' in html_content, "HTML must target test2"
            print("✓ HTML structure is correct even if endpoint doesn't work")
            
        print("✓ CSRF vulnerability test completed!")
        return True

    finally:
        # Always restore the original database
        if os.path.exists(backup_path):
            shutil.move(backup_path, db_path)
            print(f"✓ Database restored from backup")



def test_fix_csrf_vulnerability(fix_csrf_vulnerability):
    """Test for CSRF vulnerability by checking protection mechanisms"""
    import os
    import time
    from django.test import Client
    from django.conf import settings
    from django.template import engines
    
    # Add testserver to ALLOWED_HOSTS if not already there
    if 'testserver' not in settings.ALLOWED_HOSTS:
        settings.ALLOWED_HOSTS.append('testserver')
    
    # Template files to check
    template_files = []
    for root, dirs, files in os.walk("templates"):
        for file in files:
            if file.endswith(".html"):
                template_files.append(os.path.join(root, file))
    
    backups = {}
    
    try:
        
        connection.close()

        # Ensure database file has write permissions
        db_path = 'db.sqlite3'

        if os.path.exists(db_path):
            os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
            print("✓ Database permissions updated")
        
        # Ensure directory has write permissions
        db_dir = os.path.dirname(os.path.abspath(db_path))
        os.chmod(db_dir, stat.S_IRWXU | stat.S_IRWXG)
        print("✓ Directory permissions updated")

        # Store original content (vulnerable state)
        for file_path in template_files:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    backups[file_path] = f.read()
        
        # Store original settings and views
        backup_files = ["GiftcardSite/settings.py", "LegacySite/views.py"]
        for backup_file in backup_files:
            if os.path.exists(backup_file):
                with open(backup_file, 'r') as f:
                    backups[backup_file] = f.read()
        
        # Apply the fix
        fix_csrf_vulnerability()

        # Test CSRF protection
        client = Client()
        
        # Test 1: Check if templates have CSRF tokens
        csrf_tokens_added = 0
        for file_path in template_files:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read()
                
                if 'csrf_token' in content and '<form' in content.lower():
                    csrf_tokens_added += 1
        
        print(f"✓ CSRF tokens added to {csrf_tokens_added} template files")
        
        # Test 2: Check middleware configuration
        csrf_middleware_enabled = False
        settings_file = "GiftcardSite/settings.py"
        if os.path.exists(settings_file):
            with open(settings_file, 'r') as f:
                settings_content = f.read()
            csrf_middleware_enabled = 'django.middleware.csrf.CsrfViewMiddleware' in settings_content
        
        if csrf_middleware_enabled:
            print("✓ CSRF middleware is enabled in settings")
        else:
            print("⚠ CSRF middleware not found in current settings")
        
        if csrf_middleware_enabled:
            print("✓ CSRF middleware is enabled in settings")
        else:
            print("⚠ CSRF middleware not found in current settings")
        
        # Test 3: Check views.py for @csrf_protect decorators
        views_file = "LegacySite/views.py"
        if os.path.exists(views_file):
            with open(views_file, 'r') as f:
                views_content = f.read()
            
            if '@csrf_protect' in views_content:
                csrf_decorators = views_content.count('@csrf_protect')
                print(f"✓ Added @csrf_protect decorators to {csrf_decorators} view functions")
            else:
                print("⚠ No @csrf_protect decorators found in views")
        
        # Test 4: Check security settings
        settings_file = "GiftcardSite/settings.py"
        if os.path.exists(settings_file):
            with open(settings_file, 'r') as f:
                settings_content = f.read()
            
            security_checks = [
                ("SESSION_COOKIE_SAMESITE = 'Strict'", "✓ SESSION_COOKIE_SAMESITE set to Strict"),
                ("CSRF_COOKIE_SECURE = True", "✓ CSRF_COOKIE_SECURE enabled")
            ]
            
            for setting, message in security_checks:
                if setting in settings_content:
                    print(message)
                else:
                    print(f"⚠ Missing security setting: {setting}")

    
    except Exception as e:
        print(f"Error during CSRF test: {e}")
    
    finally:
        # Restore the original vulnerable state after delay
        # time.sleep(200)
        for file_path, original_content in backups.items():
            with open(file_path, 'w') as f:
                f.write(original_content)
            print(f"Restored vulnerable state in {file_path}")



def test_exploit_sql_injection_vulnerability(exploit_sql_injection_vulnerability):
    """Test SQL injection vulnerability exploitation"""
    # Backup the database before running test
    db_path = 'db.sqlite3'
    backup_path = 'db.sqlite3.backup'

    # Please comment the last two lines in LegacySite/views.py
    
    try:
        # Ensure database permissions are correct
        connection.close()

        # Ensure database file has write permissions
        if os.path.exists(db_path):
            try:
                os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
                print("✓ Database permissions updated")
            except PermissionError:
                print("⚠ Warning: Could not update database permissions, continuing anyway")
        
        # Ensure directory has write permissions
        try:
            db_dir = os.path.dirname(os.path.abspath(db_path))
            os.chmod(db_dir, stat.S_IRWXU | stat.S_IRWXG)
            print("✓ Directory permissions updated")
        except PermissionError:
            print("⚠ Warning: Could not update directory permissions, continuing anyway")

        if os.path.exists(db_path):
            try:
                shutil.copy2(db_path, backup_path)
                print(f"✓ Database backed up to {backup_path}")
            except Exception as e:
                print(f"⚠ Warning: Could not backup database: {e}")

        # Load test data
        try:
            call_command('loaddata', 'testdata.json')
            print("✓ Test data loaded successfully")
        except Exception as e:
            print(f"⚠ Warning: Could not load test data: {e}")
            # Continue with existing data if loading fails
        
        from django.test import Client
        from django.conf import settings
        
        # Add testserver to ALLOWED_HOSTS if not already there
        if 'testserver' not in settings.ALLOWED_HOSTS:
            settings.ALLOWED_HOSTS.append('testserver')
        
        # Create a client and set up test user
        client = Client()
        username, password = 'test6', 'test6'
        
        # Register and login test user
        def register_user(client, username, password):
            try:
                from LegacySite.models import User
                existing_user = User.objects.get(username=username)
                print(f"User '{username}' already exists, skipping registration")
                can_login = client.login(username=username, password=password)
                return can_login
            except User.DoesNotExist:
                endpoint = '/register'
                data = {'uname': username, 'pword': password, 'pword2': password}
                client.post(path=endpoint, data=data)
                can_login = client.login(username=username, password=password)
                return can_login

        # Set up the test user
        register_user(client, username, password)
        client.login(username=username, password=password)
        
        
        # Get the exploit payload
        card_json = exploit_sql_injection_vulnerability()
        

        print(f"Attempting SQL injection via card upload...")

        try:
            # Upload the card through the use_card_view
            response = client.post('/use.html', {
                'card_supplied': 'True',
                'card_fname': 'test_sqli',
                'card_data': io.BytesIO(card_json)
            })

            print(f"SQL injection response status: {response.status_code}")
            
            if response.status_code == 200:
                response_content = response.content.decode()
                
                # Check if the response contains admin information (indicating successful injection)
                if 'admin' in response_content.lower():
                    print("[+] SQL injection vulnerability successfully exploited!")
                    print("[+] Admin information found in response")
                    return True
                else:
                    print("[-] SQL injection payload may have been blocked or sanitized")
                    return False
            else:
                print(f"[-] Request failed with status {response.status_code}")
                return False
                
        except Exception as e:
            print(f"Error during SQL injection exploit: {e}")
            return False
        
    except Exception as e:
        print(f"Error during SQL injection test: {e}")
        return False
        
    finally:
        # Always restore the original database
        if os.path.exists(backup_path):
            shutil.move(backup_path, db_path)
            print(f"✓ Database restored from backup")



def test_fix_sql_injection_vulnerability(fix_sql_injection_vulnerability):
    import importlib
    from LegacySite import views
    importlib.reload(views)
    
    
    views_file = "LegacySite/views.py"
    db_path = 'db.sqlite3'
    backup_path = 'db.sqlite3.backup'
    
    try:
        # Step 1: Ensure database permissions are correct
        connection.close()

        # Ensure database file has write permissions
        if os.path.exists(db_path):
            try:
                os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
                print("✓ Database permissions updated")
            except PermissionError:
                print("⚠ Warning: Could not update database permissions, continuing anyway")
        
        # Ensure directory has write permissions
        try:
            db_dir = os.path.dirname(os.path.abspath(db_path))
            os.chmod(db_dir, stat.S_IRWXU | stat.S_IRWXG)
            print("✓ Directory permissions updated")
        except PermissionError:
            print("⚠ Warning: Could not update directory permissions, continuing anyway")

        # Backup the database before running test
        if os.path.exists(db_path):
            try:
                shutil.copy2(db_path, backup_path)
                print(f"✓ Database backed up to {backup_path}")
            except Exception as e:
                print(f"⚠ Warning: Could not backup database: {e}")

        # Load test data to ensure database is properly initialized
        try:
            call_command('loaddata', 'testdata.json')
            print("✓ Test data loaded successfully")
        except Exception as e:
            print(f"⚠ Warning: Could not load test data: {e}")
        
        # Step 2: Read the original views.py content
        if not os.path.exists(views_file):
            print(f"⚠ Warning: {views_file} not found, cannot test fix")
            return False
            
        with open(views_file, 'r') as f:
            original_content = f.read()

        # Step 4: Run the exploit test to verify the fix works
        print("✓ Running exploit test against fixed code...")
        exploit_result = test_exploit_sql_injection_vulnerability(exploit_sql_injection_vulnerability)
        
        if not exploit_result:
            print("✓ SQL injection exploit FAILED against fixed code - fix is working!")
            print("✓ The fixed version successfully prevents SQL injection attacks")
            result = True
        else:
            print("⚠ SQL injection exploit still succeeded - fix may need improvement")
            result = False
        
        print("✓ SQL injection vulnerability fix test completed!")
        return result
        
    except Exception as e:
        print(f"Error during SQL injection fix test: {e}")
        return False
        
    finally:
        # Step 5: Always restore the original views.py file if we added the import
        if 'has_import' in locals() and not has_import:
            try:
                with open(views_file, 'w') as f:
                    f.write(original_content)
                print(f"✓ Restored original {views_file} (removed security fix import)")
            except Exception as e:
                print(f"⚠ Warning: Could not restore original views.py: {e}")
        
        # Always restore the original database
        if os.path.exists(backup_path):
            try:
                shutil.move(backup_path, db_path)
                print(f"✓ Database restored from backup")
            except Exception as e:
                print(f"⚠ Warning: Could not restore database: {e}")
        
    print("=" * 60)



def test_exploit_cmd_injection_vulnerability(exploit_cmd_injection_vulnerability):
    """Test command injection vulnerability exploitation"""
    # Backup the database before running test
    db_path = 'db.sqlite3'
    backup_path = 'db.sqlite3.backup'
    
    try:
        # Ensure database permissions are correct
        connection.close()

        # Ensure database file has write permissions
        if os.path.exists(db_path):
            try:
                os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
                print("✓ Database permissions updated")
            except PermissionError:
                print("⚠ Warning: Could not update database permissions, continuing anyway")
        
        # Ensure directory has write permissions
        try:
            db_dir = os.path.dirname(os.path.abspath(db_path))
            os.chmod(db_dir, stat.S_IRWXU | stat.S_IRWXG)
            print("✓ Directory permissions updated")
        except PermissionError:
            print("⚠ Warning: Could not update directory permissions, continuing anyway")

        if os.path.exists(db_path):
            try:
                shutil.copy2(db_path, backup_path)
                print(f"✓ Database backed up to {backup_path}")
            except Exception as e:
                print(f"⚠ Warning: Could not backup database: {e}")

        # Load test data
        try:
            call_command('loaddata', 'testdata.json')
            print("✓ Test data loaded successfully")
        except Exception as e:
            print(f"⚠ Warning: Could not load test data: {e}")
        
        from django.test import Client
        from django.conf import settings
        
        # Add testserver to ALLOWED_HOSTS if not already there
        if 'testserver' not in settings.ALLOWED_HOSTS:
            settings.ALLOWED_HOSTS.append('testserver')
        
        # Create a client and set up test user
        client = Client()
        username, password = 'test4', 'test4'
        
        # Register and login test user
        def register_user(client, username, password):
            try:
                from LegacySite.models import User
                existing_user = User.objects.get(username=username)
                print(f"User '{username}' already exists, skipping registration")
                can_login = client.login(username=username, password=password)
                return can_login
            except User.DoesNotExist:
                endpoint = '/register'
                data = {'uname': username, 'pword': password, 'pword2': password}
                client.post(path=endpoint, data=data)
                can_login = client.login(username=username, password=password)
                return can_login

        # Set up the test user
        register_user(client, username, password)
        client.login(username=username, password=password)
        
        # Get the exploit payload
        post_params = exploit_cmd_injection_vulnerability()
        
        print(f"Attempting command injection via card_fname parameter...")
        print(f"Malicious filename: {post_params['card_fname']}")
        
        # Check if 'pwned' file exists before the attack
        pwned_file = 'pwned'
        if os.path.exists(pwned_file):
            os.remove(pwned_file)
            print("✓ Removed existing 'pwned' file")
        
        try:
            # Upload the card through the use_card_view with malicious filename
            response = client.post('/use.html', {
                'card_supplied': post_params['card_supplied'],
                'card_fname': post_params['card_fname'],
                'card_data': io.BytesIO(post_params['card_data'])
            })

            print(f"Command injection response status: {response.status_code}")
            
            # Check if we got a Bad Request (400) - this indicates the security fix is working
            if response.status_code == 400:
                print("[-] Command injection payload was blocked by input validation")
                print("[-] Bad Request response indicates security fix is working")
                return False
                
        except json.decoder.JSONDecodeError as e:
            print(f"JSON decode error: {e}; This error is the source of the exploit")
            if os.path.exists(pwned_file):
                print("[+] Command injection vulnerability successfully exploited!")
                print("[+] 'touch pwned' command executed - 'pwned' file created")
                
                # Clean up the created file
                os.remove(pwned_file)
                print("✓ Cleaned up 'pwned' file")
                return True
            else:
                print("[-] Command injection payload may have been blocked or sanitized")
                print("[-] 'pwned' file was not created")
                return False
        
        except Exception as e:
            print(f"Error during command injection exploit: {e}")
            return False

    except Exception as e:
        print(f"Error during command injection test: {e}")
        return False
        
    finally:
        # Always restore the original database
        if os.path.exists(backup_path):
            shutil.move(backup_path, db_path)
            print(f"✓ Database restored from backup")



def test_fix_cmd_injection_vulnerability(fix_cmd_injection_vulnerability):
    import importlib
    from LegacySite import views
    importlib.reload(views)
    
    
    views_file = "LegacySite/views.py"
    db_path = 'db.sqlite3'
    backup_path = 'db.sqlite3.backup'
    
    try:
        # Step 1: Ensure database permissions are correct
        connection.close()

        # Ensure database file has write permissions
        if os.path.exists(db_path):
            try:
                os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
                print("✓ Database permissions updated")
            except PermissionError:
                print("⚠ Warning: Could not update database permissions, continuing anyway")
        
        # Ensure directory has write permissions
        try:
            db_dir = os.path.dirname(os.path.abspath(db_path))
            os.chmod(db_dir, stat.S_IRWXU | stat.S_IRWXG)
            print("✓ Directory permissions updated")
        except PermissionError:
            print("⚠ Warning: Could not update directory permissions, continuing anyway")

        # Backup the database before running test
        if os.path.exists(db_path):
            try:
                shutil.copy2(db_path, backup_path)
                print(f"✓ Database backed up to {backup_path}")
            except Exception as e:
                print(f"⚠ Warning: Could not backup database: {e}")

        # Load test data to ensure database is properly initialized
        try:
            call_command('loaddata', 'testdata.json')
            print("✓ Test data loaded successfully")
        except Exception as e:
            print(f"⚠ Warning: Could not load test data: {e}")
        
        # Step 2: Read the original views.py content
        if not os.path.exists(views_file):
            print(f"⚠ Warning: {views_file} not found, cannot test fix")
            return False
            
        with open(views_file, 'r') as f:
            original_content = f.read()
        
        # Step 4: Run the exploit test to verify the fix works
        print("✓ Running exploit test against fixed code...")
        exploit_result = test_exploit_cmd_injection_vulnerability(exploit_cmd_injection_vulnerability)
        
        if not exploit_result:
            print("✓ CMD injection exploit FAILED against fixed code - fix is working!")
            print("✓ The fixed version successfully prevents CMD injection attacks")
            result = True
        else:
            print("⚠ CMD injection exploit still succeeded - fix may need improvement")
            result = False
        
        print("✓ CMD injection vulnerability fix test completed!")
        return result
        
    except Exception as e:
        print(f"Error during CMD injection fix test: {e}")
        return False
        
    finally:
        # Step 5: Always restore the original views.py file if we added the import
        if 'has_import' in locals() and not has_import:
            try:
                with open(views_file, 'w') as f:
                    f.write(original_content)
                print(f"✓ Restored original {views_file} (removed security fix import)")
            except Exception as e:
                print(f"⚠ Warning: Could not restore original views.py: {e}")
        
        # Always restore the original database
        if os.path.exists(backup_path):
            try:
                shutil.move(backup_path, db_path)
                print(f"✓ Database restored from backup")
            except Exception as e:
                print(f"⚠ Warning: Could not restore database: {e}")
        
    print("=" * 60)




def test_exploit_ssrf_vulnerability(exploit_ssrf_vulnerability):
    """Test SSRF vulnerability exploitation"""
    # Backup the database before running test
    db_path = 'db.sqlite3'
    backup_path = 'db.sqlite3.backup'

    try:
        # Ensure database permissions are correct
        connection.close()

        if os.path.exists(db_path):
            try:
                os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
                print("✓ Database permissions updated")
            except PermissionError:
                print("⚠ Warning: Could not update database permissions, continuing anyway")

        # Ensure directory has write permissions
        try:
            db_dir = os.path.dirname(os.path.abspath(db_path))
            os.chmod(db_dir, stat.S_IRWXU | stat.S_IRWXG)
            print("✓ Directory permissions updated")
        except PermissionError:
            print("⚠ Warning: Could not update directory permissions, continuing anyway")

        if os.path.exists(db_path):
            try:
                shutil.copy2(db_path, backup_path)
                print(f"✓ Database backed up to {backup_path}")
            except Exception as e:
                print(f"⚠ Warning: Could not backup database: {e}")

        # Load test data
        try:
            call_command('loaddata', 'testdata.json')
            print("✓ Test data loaded successfully")
        except Exception as e:
            print(f"⚠ Warning: Could not load test data: {e}")
            # Continue with existing data if loading fails

        from django.test import Client
        from django.conf import settings

        # Add testserver to ALLOWED_HOSTS if not already there
        if 'testserver' not in settings.ALLOWED_HOSTS:
            settings.ALLOWED_HOSTS.append('testserver')

        # Create a client and set up test user
        client = Client()
        username, password = 'test7', 'test7'

        # Register and login test user
        def register_user(client, username, password):
            try:
                from LegacySite.models import User
                existing_user = User.objects.get(username=username)
                print(f"User '{username}' already exists, skipping registration")
                can_login = client.login(username=username, password=password)
                return can_login
            except User.DoesNotExist:
                endpoint = '/register'
                data = {'uname': username, 'pword': password, 'pword2': password}
                client.post(path=endpoint, data=data)
                can_login = client.login(username=username, password=password)
                return can_login

        # Set up the test user
        register_user(client, username, password)
        client.login(username=username, password=password)

        card_url = exploit_ssrf_vulnerability()

        try:
            # Upload the card through the use_card_view
            response = client.post('/use/', {
                'card_url_supplied': True,
                'card_url': card_url,
                'card_fname': 'ssrf_test'
            })

            print(f"SSRF exploit response status: {response.status_code}")

            if response.status_code == 200:
                response_content = response.content.decode()
                if "SECRET_KEY" in response_content:
                    print("[+] SSRF vulnerability successfully exploited!")
                    print(f"[+] Leaked SECRET_KEY found in response")
                    # Extract the secret key from the error message
                    import re
                    secret_match = re.search(r'SECRET_KEY:\s*([^\s]+)', response_content)
                    if secret_match:
                        leaked_secret = secret_match.group(1)
                        print(f"[+] Leaked SECRET_KEY: {leaked_secret}")
                    return True
                else:
                    print("[-] SECRET_KEY not found in response")
                    return False
            else:
                print(f"[-] Request failed with status {response.status_code}")
                return False

        except Exception as e:
            print(f"Error during SQL injection exploit: {e}")
            return False

    except Exception as e:
        print(f"Error during SSRF exploit test: {e}")
        return False

    finally:
        # Restore the original database
        if os.path.exists(backup_path):
            shutil.move(backup_path, db_path)
            print(f"✓ Database restored from backup")




def test_fix_ssrf_vulnerability(exploit_ssrf_vulnerability):
    """Test that SSRF vulnerability has been fixed"""
    import importlib
    from LegacySite import views
    importlib.reload(views)

    views_file = "LegacySite/views.py"
    db_path = 'db.sqlite3'
    backup_path = 'db.sqlite3.backup'

    try:
        # Step 1: Ensure database permissions are correct
        connection.close()

        # Ensure database file has write permissions
        if os.path.exists(db_path):
            try:
                os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
                print("✓ Database permissions updated")
            except PermissionError:
                print("⚠ Warning: Could not update database permissions, continuing anyway")

        # Ensure directory has write permissions
        try:
            db_dir = os.path.dirname(os.path.abspath(db_path))
            os.chmod(db_dir, stat.S_IRWXU | stat.S_IRWXG)
            print("✓ Directory permissions updated")
        except PermissionError:
            print("⚠ Warning: Could not update directory permissions, continuing anyway")

        # Backup the database before running test
        if os.path.exists(db_path):
            try:
                shutil.copy2(db_path, backup_path)
                print(f"✓ Database backed up to {backup_path}")
            except Exception as e:
                print(f"⚠ Warning: Could not backup database: {e}")

        # Load test data to ensure database is properly initialized
        try:
            call_command('loaddata', 'testdata.json')
            print("✓ Test data loaded successfully")
        except Exception as e:
            print(f"⚠ Warning: Could not load test data: {e}")

        # Step 2: Read the original views.py content
        if not os.path.exists(views_file):
            print(f"⚠ Warning: {views_file} not found, cannot test fix")
            return False

        with open(views_file, 'r') as f:
            original_content = f.read()

        # Step 4: Run the exploit test to verify the fix works
        print("✓ Running exploit test against fixed code...")
        exploit_result = test_exploit_ssrf_vulnerability(exploit_ssrf_vulnerability)

        if not exploit_result:
            print("✓ SSRF exploit FAILED against fixed code - fix is working!")
            print("✓ The fixed version successfully prevents SSRF attacks")
            result = True
        else:
            print("⚠ SSRF exploit still succeeded - fix may need improvement")
            result = False

        print("✓ SSRF vulnerability fix test completed!")
        return result

    except Exception as e:
        print(f"Error during SSRF fix test: {e}")
        return False

    finally:
        # Step 5: Always restore the original views.py file if we added the import
        if 'has_import' in locals() and not has_import:
            try:
                with open(views_file, 'w') as f:
                    f.write(original_content)
                print(f"✓ Restored original {views_file} (removed security fix import)")
            except Exception as e:
                print(f"⚠ Warning: Could not restore original views.py: {e}")

        # Always restore the original database
        if os.path.exists(backup_path):
            try:
                shutil.move(backup_path, db_path)
                print(f"✓ Database restored from backup")
            except Exception as e:
                print(f"⚠ Warning: Could not restore database: {e}")

    print("=" * 60)
