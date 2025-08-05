# %%
from mitmproxy import http
from typing import List

print("above-class flag--------------------")

class RequestBlocker:
    def request(self, flow: http.HTTPFlow) -> None:
        """
        Intercept and potentially block HTTP requests.

        This method is called by mitmproxy for every HTTP request.
        If the request is to a blocked domain, we create a fake response
        instead of forwarding the request.

        Args:
            flow: The HTTP flow object containing request and response
        """
        """
        prettyhost = flow.request.pretty_host
        evilthing = "evil.aisb.dev"
        print(prettyhost)
        if evilthing in prettyhost:
            flow.response = http.Response.make({"Content-Type": "text/html"},status_code = 200, content=b"intercepted and blocked request :)")
            print("request was blocked")
        # TODO: Implement request blocking
        #   1. Check if flow.request.pretty_host contains "evil.aisb.dev"
        #   2. If blocked, create a response (flow.response = http.Response.make(...)) with:
        #      - Status code 200
        #      - Body: b"intercepted and blocked request :)"
        #   3. Print a message indicating the request was blocked
        """
        print("pther part")
        blocked_hosts = ["evil.aisb.dev"]

        # Check if the request host matches any blocked domain
        if any(host in flow.request.pretty_host for host in blocked_hosts):
            # Create a blocked response
            flow.response = http.Response.make(
                200, b"intercepted and blocked request :)", {"Content-Type": "text/html"}
            )
            print(f"Blocked: {flow.request.pretty_url}")


# Initialize the addon for mitmproxy
addons: list = []
addons = [RequestBlocker()]
print("between-class flag-------------")
# %%
from mitmproxy import dns as mitmproxydns  # alias to avoid conflict with dnspython
import base64


def get_packet(question, request):
    msg_cls = (
        mitmproxydns.DNSMessage if hasattr(mitmproxydns, "DNSMessage") else mitmproxydns.Message
    )  # mac has Message, linux has DNSMessage ??
    return msg_cls(
        id=request.id,  # Match the request's transaction ID
        op_code=0,  # Standard query opcode
        authoritative_answer=False,  # Not authoritative
        truncation=False,  # Not truncated
        recursion_desired=True,  # RD flag set
        recursion_available=True,  # RA flag set
        response_code=0,  # NOERROR
        questions=request.questions,
        answers=[
            mitmproxydns.ResourceRecord(
                name=question.name,
                type=question.type,
                class_=question.class_,
                ttl=60,
                # this is intentionally base64 encoded - look at exercise 8.1a for more details
                data=base64.decodebytes(b"GGJsb2NrZWQgYnkgRE5TIGZpbHRlciA6KQ=="),
            )
        ],
        authorities=[],  # No authority records
        additionals=[],  # No additional records
        timestamp=request.timestamp,
        query=False,  # This is a response, not a query
        reserved=0,  # Reserved bits must be 0
    )


class DNSInterceptor:
    """
    Intercept and modify TXT requests to any subdomain of evil.aisb.dev.

    This addon demonstrates how to read and rewrite DNS requests
    """

    def dns_request(self, flow: mitmproxydns.DNSFlow) -> None:
        """
        Intercept DNS requests before they are sent to the upstream server.

        You need to:
        1. Check if the flow contains a request
        2. Iterate through questions in the request
        3. Identify TXT record queries (type == 16)
        4. Block queries to suspicious domains

        Args:
            flow: The DNS flow object containing the DNS query
        """
        if "SOLUTION":
            print("[DNS] Intercepting DNS request...")

            # Check if this is a query (not a response)
            if flow.request:
                # Iterate through all questions in the DNS query
                for question in flow.request.questions:
                    # Check if it's a TXT record query (type 16)
                    if question.type == 16:  # TXT record type
                        print(f"[DNS] TXT query intercepted: {question.name}")

                        # List of domains to block
                        blocked_domains = ["evil.aisb.dev", "attacker.com", "malicious.net"]

                        # Check if the query is for a blocked domain
                        if any(domain in question.name for domain in blocked_domains):
                            # Create a fake response to block the query
                            flow.response = get_packet(question, flow.request)
                            print(f"[DNS] Blocked TXT query for: {question.name}")
                            return

                    # Log other query types for monitoring
                    else:
                        print(f"[DNS] Allowing {question.type} query for: {question.name}")
        else:
            # TODO: Implement DNS filtering
            #   1. Check if flow.request exists
            #   2. Loop through flow.request.questions
            #   3. Check if question.type == 16 (TXT record)
            #   4. If question.name is a blocked domain:
            #      - Set flow.response = get_dns_block_response(question, flow.request)
            pass

addons = [RequestBlocker(), DNSInterceptor()]
print("addons set correctly")
# %%


