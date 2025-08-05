from mitmproxy import http
from typing import List
from mitmproxy import dns as mitmproxydns  # alias to avoid conflict with dnspython
import base64


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

        if "evil.aisb.dev" in flow.request.pretty_host.lower():
            flow.response = http.Response.make(status_code=200, content=b"intercepted and blocked request :)")
            print("Request blocked!")
        else:
            print("Ummm")


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
        if getattr(flow, "request") is not None and (req := flow.request) is not None:
            for q in req.questions:
                if q.type == 16:
                    print(f"{q.name} found")

                    if "evil.aisb.dev" in q.name.lower():
                        flow.response = get_packet(q, flow.request)
                        print(f"{q.name} BLOCKED")
        else:
            print("Bad")


addons = [RequestBlocker(), DNSInterceptor()]
