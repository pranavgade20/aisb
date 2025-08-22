import json
import threading
import time

import requests



class MCPClient:
    def __init__(self, url_base):
        self.url_base = url_base
        self.endpoint = None
        self.messages: list[dict] = []
        self.server_info = None
        self.id = 0

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

        url = f"{self.url_base}/sse"
        response = requests.get(url, stream=True)

        for line in response.iter_lines(decode_unicode=True):
            # print(line)
            if line and line.startswith("data: "):
                line = line.removeprefix("data: ").strip()
                if "/messages" in line:
                    self.endpoint = line
                else:
                    self.messages.append(json.loads(line))

    def send_message(self, message):
        """
        Send a message to the MCP server.
        :param message: The message to send.
        :return: The response from the MCP server.
        """
        if not self.endpoint:
            raise ValueError("Endpoint is not set. Connect to the MCP server first.")
        # todo: send a message to the MCP server
        url = f"{self.url_base}{self.endpoint}"
        response = requests.post(url, json=message)

        self.id += 1
        if 200 <= response.status_code < 300:
            return response
        else:
            raise ValueError(f"Error {response.status_code}: {response.text}")

    def get_message(self):
        """
        Get the latest message from the MCP server.
        :return: The latest message received from the MCP server.
        """
        # todo: wait for a message to show up in the queue and return it
        
        while len(self.messages) == 0:
            time.sleep(0.1)

        return self.messages.pop(0)
        # return self.messages[-1]

    def handshake(self):
        """
        Hansdshake with the MCP server to initialize the connection.
        """
        if not self.endpoint:
            raise ValueError("Endpoint is not set. Connect to the MCP server first.")
        # todo: implement the handshake with the MCP server
        #   - Send an initialization message to the MCP server with the protocol version and client info.
        #   - Wait for the server's response and store it in self.server_info
        message = {
            "jsonrpc": "2.0",
            "id": self.id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"roots": {"listChanged": True}, "sampling": {}, "elicitation": {}},
                "clientInfo": {
                    "name": "ExampleClient",
                    "title": "Example Client Display Name",
                    "version": "1.0.0",
                },
            },
        }

        self.send_message(message)
        message = self.get_message()
        self.server_info = message["result"]["serverInfo"]


        notification = {
            'jsonrpc': '2.0',
            'method': 'notifications/initialized'
        }
        self.send_message(notification)

        # print(self.server_info)

    def get_resources(self, cursor=None):
        """
        Get resources from the MCP server.
        :param cursor: Optional cursor for pagination.
        :return: List of resources.
        """
        # todo: implement the logic to list resources on the MCP server
        payload = {
          "jsonrpc": "2.0",
          "id": self.id,
          "method": "resources/list",
          "params": {
            "cursor": cursor
          }
        }

        self.send_message(payload)
        message = self.get_message()

        return message['result']['resources']


    def get_tools(self, cursor=None):
        """
        Get tools from the MCP server.
        :param cursor: Optional cursor for pagination.
        :return: List of tools.
        """
        # todo: implement the logic to list tools on the MCP server
        payload = {
          "jsonrpc": "2.0",
          "id": self.id,
          "method": "tools/list",
          "params": {
            "cursor": cursor
          }
        }

        self.send_message(payload)
        message = self.get_message()

        return message['result']['tools']

    def access_resource(self, resource_uri):
        """
        Access a specific resource by its URI.
        :param resource_uri: The URI of the resource to access.
        :return: The resource data.
        """
        # todo: implement the logic to access a resource by its URI
        payload = {
          "jsonrpc": "2.0",
          "id": self.id,
          "method": "resources/read",
          "params": {
            "uri": resource_uri
          }
        }

        self.send_message(payload)
        message = self.get_message()

        return message['result']['contents']

if __name__ == "__main__":
    # Example usage
    mcp_client = MCPClient("https://0.mcp.aisb.dev")
    thread = threading.Thread(target=mcp_client.connect, daemon=True).start()
    while not mcp_client.endpoint:
        time.sleep(0.1)
        print(".", end="")
    mcp_client.handshake()
    resources = mcp_client.get_resources()
    tools = mcp_client.get_tools()
    resource_response = mcp_client.access_resource(resources[0]['uri'])

    print(resource_response)
