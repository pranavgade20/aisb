from mitmproxy import http
from typing import List


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


# Initialize the addon for mitmproxy
addons: list = []
addons = [RequestBlocker()]
