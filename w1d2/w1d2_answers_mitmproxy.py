from typing import List

from mitmproxy import http


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
        # TODO: Implement request blocking
        #   1. Check if flow.request.pretty_host contains "evil.aisb.dev"
        if "evil.aisb.dev" not in flow.request.pretty_host:
            return
        #   2. If blocked, create a response (flow.response = http.Response.make(...)) with:
        flow.response = http.Response.make(status_code=200, content=b"intercepted and blocked request :)")
        #      - Status code 200
        #      - Body: b"intercepted and blocked request :)"
        #   3. Print a message indicating the request was blocked
        print("YOU GOT PWND")


import base64

from mitmproxy import dns as mitmproxydns  # alias to avoid conflict with dnspython

# Initialize the addon for mitmproxy
addons: list = []
addons = [RequestBlocker()]

# %%


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


from mitmproxy.dns import DNSMessage, Question, ResourceRecord

# def get_dns_block_response(question: Question, request: DNSMessage)-> DNSMessage:
#     return DNSMessage(
#         id=request.id,
#         query=False,
#         op_code=request.op_code,
#         authoritative_answer=True,
#         truncation=False,
#         recursion_desired=request.recursion_desired,
#         recursion_available=True,
#         reserved=0,
#         response_code=TODO,
#         questions=[request.question],
#         answers=[ResourceRecord(??)],
#         authorities=[request.authority],
#         additionals=[request.additional],
#     )



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
        print("INSIDE INTERCEPTOR")
        TXT_RECORD_TYPE = 16
        for question in flow.request.questions:
            if question.type != TXT_RECORD_TYPE:
                continue
            if question.name.endswith("evil.aisb.dev"):
                print("FOUND A SUSPICIOUS REQUEST ")
                print("request", flow.request)
                print("response", flow.response)
                flow.response = get_packet(question, flow.request)
        # TODO: Implement DNS filtering
        #   1. Check if flow.request exists
        #   2. Loop through flow.request.questions
        #   3. Check if question.type == 16 (TXT record)
        #   4. If question.name is a blocked domain:
        #      - Set flow.response = get_dns_block_response(question, flow.request)
        pass


addons = [RequestBlocker(), DNSInterceptor()]
