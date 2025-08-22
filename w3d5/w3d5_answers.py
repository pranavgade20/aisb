import json
import threading
import time
from collections.abc import Iterable

import requests


class UnknownEventError(RuntimeError):
    pass


#
class MCPClient:
    def __init__(self, url_base):
        self.url_base: str = url_base
        self.endpoint = None
        self.messages = []
        self.server_info = None

    def connect(self):
        s = requests.Session()
        sse_endpoint = self.url_base + "/sse"

        current_event = []

        with s.get(sse_endpoint, headers=None, stream=True) as resp:
            for line in resp.iter_lines():
                decoded_line: str = line.decode("utf-8")
                if decoded_line == "":
                    self._process_event(current_event)
                    current_event = []
                else:
                    current_event.append(decoded_line)
            # lines_iter: Iterable[bytes] = resp.iter_lines()
            # for line in lines_iter:
            # print("next")
            # decoded: str = line.decode("utf-8")
            # print(decoded)
            # if "event: endpoint" in decoded:
            #     data_line = next(lines_iter).decode("utf-8")
            #     assert data_line.startswith("data: ")
            #     session_endpoint = data_line.rstrip("data: ")
            #     self.endpoint = session_endpoint
            #     print(f"Endpoint = {self.endpoint}")

    def _process_event(self, event: list[str]):
        if len(event) == 2 and event[0] == ("event: endpoint") and event[1].startswith("data"):
            endpoint = event[1].removeprefix("data: ")
            print(f"Found endpoint: {endpoint}")
            self.endpoint = self.url_base + "/" + endpoint
        elif len(event) == 1 and event[0].startswith(": ping - "):
            print("Found ping, skipping")
            pass
        elif len(event) == 2 and event[0] == ("event: message") and event[1].startswith("data"):
            msg = event[1].removeprefix("data: ")
            print(f"Found endpoint: {msg}")
            json_data = json.loads(msg)
            self.messages.append(json_data)
        else:
            print(f"Unknown event: {event}")
            raise UnknownEventError(event)

    def send_message(self, message):
        """
        Send a message to the MCP server.
        :param message: The message to send.
        :return: The response from the MCP server.
        """
        if not self.endpoint:
            raise ValueError("Endpoint is not set. Connect to the MCP server first.")
        # todo: send a message to the MCP server
        print(message)
        # eg "message": "tools/methods"
        
        headers = {'Accept': 'application/json, text/event-stream', 
                   "Content-Type": "application/json"}
        json_rpc_msg = json.dumps(message)

        resp = requests.post(self.endpoint, data=json_rpc_msg, headers=headers)
        assert resp.ok, f"expected OK got {resp.status_code}"
        print(f"response: {resp.text}")
        while len(self.messages) == 0:
            time.sleep(0.5)
        return self.messages.pop()

        

    def get_message(self):
        """
        Get the latest message from the MCP server.
        :return: The latest message received from the MCP server.
        """
        # todo: wait for a message to show up in the queue and return it
        pass

    def handshake(self):
        """
        Hansdshake with the MCP server to initialize the connection.
        """
        if not self.endpoint:
            raise ValueError("Endpoint is not set. Connect to the MCP server first.")
        # todo: implement the handshake with the MCP server
        #   - Send an initialization message to the MCP server with the protocol version and client info.
        #   - Wait for the server's response and store it in self.server_info
        pass

    def get_resources(self, cursor=None):
        """
        Get resources from the MCP server.
        :param cursor: Optional cursor for pagination.
        :return: List of resources.
        """
        # todo: implement the logic to list resources on the MCP server
        pass

    def get_tools(self, cursor=None):
        """
        Get tools from the MCP server.
        :param cursor: Optional cursor for pagination.
        :return: List of tools.
        """
        # todo: implement the logic to list tools on the MCP server
        pass

    def access_resource(self, resource_uri):
        """
        Access a specific resource by its URI.
        :param resource_uri: The URI of the resource to access.
        :return: The resource data.
        """
        # todo: implement the logic to access a resource by its URI
        pass


if __name__ == "__main__":
    # Example usage
    mcp_client = MCPClient("https://0.mcp.aisb.dev")
    

    print("started thread")
    thread = threading.Thread(target=mcp_client.connect).start()
    print("after thread")
    while not mcp_client.endpoint:
        time.sleep(0.1)
        print("in the loop")
        print(".", end="")
    print(f"endpoint is: {mcp_client.endpoint}")
    mcp_client.handshake()
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
            "roots": {
                "listChanged": True
            },
            "sampling": {},
            "elicitation": {}
            },
            "clientInfo": {
            "name": "ExampleClient",
            "title": "Example Client Display Name",
            "version": "1.0.0"
            }
        }
    }
    print("about to send msg")
    resp = mcp_client.send_message(message)
    print(f"response: {resp}")
