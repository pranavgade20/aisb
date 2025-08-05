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


# Initialize the addon for mitmproxy
addons: list = []
addons = [RequestBlocker()]
