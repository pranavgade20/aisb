import json
import threading
import time
from dataclasses import dataclass

import requests
from rich import print


class UnknownEventError(RuntimeError):
    pass


JSONRPC = dict[str, str]
Tool = dict[str, str]
# Resource = dict[str, str]


@dataclass
class Resource:
    uri: str
    name: str
    description: str
    mimeType: str
    title: str | None = None


class MCPClient:
    def __init__(self, url_base):
        self.url_base: str = url_base
        self.endpoint = None
        self.messages = []
        self.server_info = None
        self.protocol_version = "2024-11-05"

    def connect(self):
        s = requests.Session()
        sse_endpoint = self.url_base + "/sse"

        current_event = []

        with s.get(sse_endpoint, headers=None, stream=True) as resp:
            for line in resp.iter_lines():
                decoded_line: str = line.decode("utf-8")
                print(decoded_line)
                if decoded_line == "":
                    self._process_event(current_event)
                    current_event = []
                else:
                    current_event.append(decoded_line)

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
            print(f"Got msg: {msg}")
            json_data = json.loads(msg)
            self.messages.append(json_data)
        else:
            print(f"Unknown event: {event}")
            raise UnknownEventError(event)

    def send_message(self, message: JSONRPC) -> requests.Response:
        """
        Send a message to the MCP server.
        :param message: The message to send.
        :return: The response from the MCP server.
        """
        if not self.endpoint:
            raise ValueError("Endpoint is not set. Connect to the MCP server first.")

        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": self.protocol_version,
        }
        # TODO(rs) delete?
        # if self.server_info:
        #     headers["MCP-Protocol-Version"] = self.server_info["result"]["protocol_version"]
        json_rpc_msg = json.dumps(message)

        resp = requests.post(self.endpoint, data=json_rpc_msg, headers=headers)
        assert resp.ok, f"expected OK got {resp.status_code}. Response: {resp.text}"
        return resp

    def get_message(self):
        """
        Get the latest message from the MCP server.
        :return: The latest message received from the MCP server.
        """
        while len(self.messages) == 0:
            time.sleep(0.5)
        return self.messages.pop()

    def handshake(self):
        """
        Hansdshake with the MCP server to initialize the connection.
        """
        if not self.endpoint:
            raise ValueError("Endpoint is not set. Connect to the MCP server first.")

        initialize_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": self.protocol_version,
                "capabilities": {"roots": {"listChanged": True}, "sampling": {}, "elicitation": {}},
                "clientInfo": {"name": "w3d5-diana-rusheb", "title": "Diana and Rusheb", "version": "1.0.0"},
            },
        }
        self.send_message(initialize_request)
        self.server_info = self.get_message()

        print("Sending init")
        initialized_notification = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }
        resp = self.send_message(initialized_notification)
        print(f"Init resp {resp}")
        print("Handshake complete")

    def get_resources(self, cursor=None) -> list[Resource]:
        """
        Get resources from the MCP server.
        :param cursor: Optional cursor for pagination.
        :return: List of resources.
        """
        # todo: implement the logic to list resources on the MCP server
        get_resourses_message = {"jsonrpc": "2.0", "id": 1, "method": "resources/list", "params": {}}
        if cursor:
            get_resourses_message["params"]["cursor"] = cursor
        self.send_message(get_resourses_message)
        resp = self.get_message()
        resources = [Resource(**r) for r in resp["result"]["resources"]]
        return resources

    def get_tools(self, cursor=None) -> list[Tool]:
        """
        Get tools from the MCP server.
        :param cursor: Optional cursor for pagination.
        :return: List of tools.
        """
        # todo: implement the logic to list tools on the MCP server
        get_tools_message = {
            "jsonrpc": "2.0",
            "id": "1",
            "method": "tools/list",
            "params": {},
        }
        if cursor:
            get_tools_message["params"]["cursor"] = cursor

        self.send_message(get_tools_message)
        resp = self.get_message()
        tools = resp["result"]["tools"]
        return tools

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
        print(".", end="")
    print(f"endpoint is: {mcp_client.endpoint}")
    mcp_client.handshake()

    print("tools:", mcp_client.get_tools())
    print("resources:", mcp_client.get_resources())


## TODO
# - request ID?
