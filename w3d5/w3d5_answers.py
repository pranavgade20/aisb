# %%
import json
import threading
import time

import requests


class MCPClient:
    def __init__(self, url_base):
        self.url_base = url_base
        self.endpoint = None
        self.messages = []
        self.server_info = None

    def connect(self):
        """
        Connect to the MCP server and listen for messages.
        This method uses Server-Sent Events (SSE) to receive real-time updates from the MCP server.

        self.endpoint will be set to the endpoint URL provided by the MCP server.
        messages received from the MCP server will be stored in self.messages.
        :return:
        """
        print(f"Connecting to MCP at {self.url_base}")
        response = requests.get(self.url_base + "/sse", stream=True)

        if response.status_code != 200:
            print(f"Failed to connect to MCP: {response.status_code}")
            return
        state = None
        for line in response.iter_lines():
            if line:
                print(line.decode("utf-8"))

                if line.startswith(b": ping"):
                    pass
                elif line.startswith(b"event: endpoint"):
                    state = "endpoint"
                elif line.startswith(b"event: message"):
                    state = "message"
                elif line.startswith(b"data: "):
                    if state == "endpoint":
                        self.endpoint = line[6:].strip().decode("utf-8")
                    elif state == "message":
                        self.messages.append(json.loads(line[6:].strip()))
                    else:
                        raise AssertionError(f"Got line {line} in unexpected state {state}")
                else:
                    raise AssertionError("I don't know what to do with this line: " + line)

    def send_message(self, message):
        """
        Send a message to the MCP server.
        :param message: The message to send.
        :return: The response from the MCP server.
        """
        if not self.endpoint:
            raise ValueError("Endpoint is not set. Connect to the MCP server first.")


        response = requests.post(self.url_base + self.endpoint, json=message)
        if not 200 <= response.status_code < 300:
            raise Exception(f"Failed to send message: {response.status_code} - {response.text}")

        return response.text


    def get_message(self):
        """
        Get the latest message from the MCP server.
        :return: The latest message received from the MCP server.
        """

        while len(self.messages) == 0:
            time.sleep(0.1)  # Wait for a message to be received
        return self.messages.pop(0)


    def handshake(self):
        """
        Hansdshake with the MCP server to initialize the connection.
        """
        if not self.endpoint:
            raise ValueError("Endpoint is not set. Connect to the MCP server first.")

        init_message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "AISB Client", "title": "Test Client for MCP", "version": "1.0.0"},
            },
        }

        self.send_message(init_message)

        self.server_info = self.get_message()

        finish_init = {"jsonrpc": "2.0", "method": "notifications/initialized"}

        self.send_message(finish_init)

        print("Handshake complete. Client initialized.")

    def get_resources(self, cursor=None):
        """
        Get resources from the MCP server.
        :param cursor: Optional cursor for pagination.
        :return: List of resources.
        """
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/list",
            "params": {"cursor": cursor} if cursor else {},
        }
        self.send_message(message)
        response = self.get_message()
        return response.get("result", {}).get("resources", [])


    def get_tools(self, cursor=None):
        """
        Get tools from the MCP server.
        :param cursor: Optional cursor for pagination.
        :return: List of tools.
        """

        message = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"cursor": cursor}}
        self.send_message(message)
        response = self.get_message()
        return response.get("result", {}).get("tools", [])


    def access_resource(self, resource_uri):
        """
        Access a specific resource by its URI.
        :param resource_uri: The URI of the resource to access.
        :return: The resource data.
        """

        message = {"jsonrpc": "2.0", "id": 2, "method": "resources/read", "params": {"uri": resource_uri}}

        self.send_message(message)
        response = self.get_message()
        if "result" in response:
            return response
        elif "error" in response:
            raise Exception(f"Error accessing resource: {response['error']}")
        else:
            raise Exception("Unexpected response format: " + json.dumps(response))


# Example usage
mcp_client = MCPClient("https://0.mcp.aisb.dev")
thread = threading.Thread(target=mcp_client.connect, daemon=True).start()
while not mcp_client.endpoint:
    time.sleep(0.1)
    print(".", end="")
mcp_client.handshake()
