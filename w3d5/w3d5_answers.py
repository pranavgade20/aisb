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
        # todo: Implement the connection logic to the MCP server
        #   - Start by making a GET request to the MCP server's SSE endpoint and stream the r.
        #   - Parse the incoming lines to extract the messages
        #   - Store the endpoint URL in self.endpoint and push the messages to self.messages
        #   - Have a lower bar for looking at the solution for this one if you don't know how http streaming works
        r = requests.get(self.url_base + "/sse", stream=True)
        if r.status_code != 200:
            print(f"Failed to connect to MCP: {r.status_code}")
            return
        state = None
        for line in r.iter_lines():
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
        :return: The r from the MCP server.
        """
        print(message)
        if not self.endpoint:
            raise ValueError("Endpoint is not set. Connect to the MCP server first.")
        # todo: send a message to the MCP server
        response = requests.post(self.url_base + self.endpoint, json=message)
        if not 200 <= response.status_code < 300:
            raise Exception(f"Failed to send message: {response.status_code} - {response.text}")

        return response.text

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
        #   - Wait for the server's r and store it in self.server_info
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
        # todo: implement the logic to list resources on the MCP server
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
        # todo: implement the logic to list tools on the MCP server
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
        # todo: implement the logic to access a resource by its URI
        message = {"jsonrpc": "2.0", "id": 2, "method": "resources/read", "params": {"uri": resource_uri}}

        self.send_message(message)
        response = self.get_message()
        if "result" in response:
            return response
        elif "error" in response:
            raise Exception(f"Error accessing resource: {response['error']}")
        else:
            raise Exception("Unexpected response format: " + json.dumps(response))

    # def access_tool(self, tool_name, **kwargs):
    #     """
    #     Access a specific tool by its name.
    #     :param tool_name: The name of the tool to access.
    #     :param params: The parameters for the tool as a dictionary.
    #     :return: The tool execution result.
    #     """
    #     # message = {"jsonrpc": "2.0", "id": 3, "method": "tools/run", "params": {"tool": tool_name, "input": params}}
    #     # self.send_message(message)
    #     # response = self.get_message()
    #     # if "result" in response:
    #     #     return response
    #     # elif "error" in response:
    #     #     raise Exception(f"Error accessing tool: {response['error']}")
    #     # else:
    #     #     raise Exception("Unexpected response format: " + json.dumps(response))
    #     # Validate tool name
    #     if tool_name not in ['execute_command', 'read_file']:
    #         raise ValueError(f"Invalid tool name: {tool_name}")

    #     # Prepare parameters based on tool
    #     if tool_name == 'execute_command':
    #         if 'command' not in kwargs:
    #             raise ValueError("'command' parameter is required for execute_command")
    #         params = {'command': kwargs['command']}

    #     elif tool_name == 'read_file':
    #         if 'filename' not in kwargs:
    #             raise ValueError("'filename' parameter is required for read_file")
    #         params = {'filename': kwargs['filename']}

    #     # Make the API call
    #     response = self.post(f"/tools/{tool_name}", json=params)
    #     return response.json()

    def access_tool(self, tool_name: str, params: dict) -> dict:
        """
        Access MCP tools with proper parameters.

        Args:
            tool_name: Name of the tool to access ('execute_command' or 'read_file')
            **kwargs: Tool-specific parameters

        Returns:
            dict: Tool execution result

        Raises:
            ValueError: If invalid tool name or missing required parameters
        """
        # Validate tool name
        if tool_name not in ["execute_command", "read_file"]:
            raise ValueError(f"Invalid tool name: {tool_name}")

        # Prepare the JSON-RPC message with the tool arguments at the top level.
        message = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": params},
        }
        # Send the message and get response
        self.send_message(message)
        response = self.get_message()

        # Handle the response
        if "result" in response:
            return response
        elif "error" in response:
            raise Exception(f"Error accessing tool: {response['error']}")
        else:
            raise Exception("Unexpected response format: " + json.dumps(response))


# %%
if True:
    # Example usage
    mcp_client = MCPClient("https://0.mcp.aisb.dev")
    thread = threading.Thread(target=mcp_client.connect, daemon=True).start()
    while not mcp_client.endpoint:
        time.sleep(0.1)
        print(".", end="")
    mcp_client.handshake()

# %%
mcp_client.get_tools()

# %%
mcp_client.get_resources()

mcp_client.access_resource("internal://credentials")

"""{'jsonrpc': '2.0',
 'id': 2,
 'result': {'contents': [{'uri': 'internal://credentials',
    'mimeType': 'text/plain',
    'text': '\n            SYSTEM CREDENTIALS\n            ------------------\n            Admin Username: admin_user\n            Admin Password: super_secret_password123\n            API Key: sk-a1b2c3d4e5f6g7h8i9j0\n            Database Connection String: postgresql://dbuser:dbpass@localhost/production\n            '}]}}"""

# %%

base_url_1 = "https://1.mcp.aisb.dev"
base_url_2 = "https://2.mcp.aisb.dev"


# %%
if True:
    # Example usage
    mcp_client = MCPClient(base_url_1)
    thread = threading.Thread(target=mcp_client.connect, daemon=True).start()
    while not mcp_client.endpoint:
        time.sleep(0.1)
        print(".", end="")
    mcp_client.handshake()


# %%
mcp_client.get_resources()
mcp_client.get_tools()
# %%
result = mcp_client.access_tool("execute_command", params={"command": "whoami"})
print(result["result"])
# %%
