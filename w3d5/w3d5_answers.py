# %%
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

        # The local path where you want to save the downloaded file.
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
        # todo: send a message to the MCP server

        pass

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


# Example usage
mcp_client = MCPClient("https://0.mcp.aisb.dev")
thread = threading.Thread(target=mcp_client.connect, daemon=True).start()
while not mcp_client.endpoint:
    time.sleep(0.1)
    print(".", end="")
mcp_client.handshake()
