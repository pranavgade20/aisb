import json
import threading
import time

import requests


#
class MCPClient:
    def __init__(self, url_base):
        self.url_base = url_base
        self.endpoint = None
        self.messages = []
        self.server_info = None
        self.resources = None

    def connect(self):
        """
        Connect to the MCP server and listen for messages.
        This method uses Server-Sent Events (SSE) to receive real-time updates from the MCP server.

        self.endpoint will be set to the endpoint URL provided by the MCP server.
        messages received from the MCP server will be stored in self.messages.
        :return:
        """
        # todo: Implement the connection logic to the MCP server
        #   - Start by making a GET request to the MCP server's SSE endpoint and stream the response.
        #   - Parse the incoming lines to extract the messages
        #   - Store the endpoint URL in self.endpoint and push the messages to self.messages
        #   - Have a lower bar for looking at the solution for this one if you don't know how http streaming works
        try:
            endpoint = self.url_base + "/sse"
            response = requests.get(endpoint, stream=True)

            eventType = None
            for line in response.iter_lines():
                print(line.decode("utf-8"))
                if line:
                    if line.startswith(b"event: endpoint"):
                        eventType = "endpoint"
                    if line.startswith(b"event: message"):
                        eventType = "message"

                    if line.startswith(b"data: "):
                        if eventType == "endpoint":
                            self.endpoint = line[6:].strip().decode("utf-8")
                        if eventType == "message":
                            self.messages.append(json.loads(line[6:].strip()))

        except Exception as e:
            print(e)

    def send_message(self, message):
        """
        Send a message to the MCP server.
        :param message: The message to send.
        :return: The response from the MCP server.
        """
        if not self.endpoint:
            raise ValueError("Endpoint is not set. Connect to the MCP server first.")
        # todo: send a message to the MCP server
        try:
            requests.post(self.url_base + self.endpoint, json=message)
        except Exception as e:
            print(e)

    def get_message(self):
        """
        Get the latest message from the MCP server.
        :return: The latest message received from the MCP server.
        """
        # todo: wait for a message to show up in the queue and return it

        while len(self.messages) == 0:
            time.sleep(0.1)  # Wait for a message to be received

        return self.messages.pop(0)

    def handshake(self):
        """
        Hansdshake with the MCP server to initialize the connection.
        """
        if not self.endpoint:
            raise ValueError("Endpoint is not set. Connect to the MCP server first.")
        # todo: implement the handshake with the MCP server
        #   - Send an initialization message to the MCP server with the protocol version and client info.
        #   - Wait for the server's response and store it in self.server_info
        try:
            payload = {
                "jsonrpc": "2.0",
                "id": 25,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"roots": {"listChanged": True}, "sampling": {}, "elicitation": {}},
                    "clientInfo": {"name": "ExampleClient", "title": "Example Client Display Name", "version": "1.0.0"},
                },
            }

            self.send_message(payload)
            self.server_info = self.get_message()

            finish_init = {"jsonrpc": "2.0", "method": "notifications/initialized"}

            self.send_message(finish_init)
            print("Handshake complete. Client initialized.")
        except Exception as e:
            print(e)

    def get_resources(self, cursor=None):
        """
        Get resources from the MCP server.
        :param cursor: Optional cursor for pagination.
        :return: List of resources.
        """
        # todo: implement the logic to list resources on the MCP server
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/list",
        }

        self.send_message(payload)
        response = self.get_message()

        self.resources = response["result"]["resources"]

        print("Resources")
        print(response["result"]["resources"])

    def get_tools(self, cursor=None):
        """
        Get tools from the MCP server.
        :param cursor: Optional cursor for pagination.
        :return: List of tools.
        """
        # todo: implement the logic to list tools on the MCP server
        payload = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
        }

        self.send_message(payload)
        response = self.get_message()

        print()
        print("Tools:")
        print(response["result"]["tools"])

    def access_resource(self, resource_uri):
        """
        Access a specific resource by its URI.
        :param resource_uri: The URI of the resource to access.
        :return: The resource data.
        """
        # todo: implement the logic to access a resource by its URI
        payload = {"jsonrpc": "2.0", "id": 2, "method": "resources/read", "params": {"uri": resource_uri}}

        self.send_message(payload)
        response = self.get_message()

        print()
        print(response)


if True:
    # Example usage
    mcp_client = MCPClient("https://0.mcp.aisb.dev")
    thread = threading.Thread(target=mcp_client.connect, daemon=True).start()
    while not mcp_client.endpoint:
        time.sleep(0.1)
        print(".", end="")

    mcp_client.handshake()
    mcp_client.get_resources()
    mcp_client.get_tools()
    mcp_client.access_resource(mcp_client.resources[0]["uri"])
