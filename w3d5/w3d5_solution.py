"""
#W3D5 - Hardware Security & LLM Applications (MCP, RAG)

Today, we'll extend yesterday's exercises with a quick exercise on physical security until lunch. Then, we'll look at MCP (Model Context Protocol) and RAG (Retrieval-Augmented Generation) systems.

## Exercise 1: Hardware Supply Chain Security

### Exercise 1.1: Reading and Discussion
Start by reading:
- https://www.bunniestudios.com/blog/2019/can-we-build-trustable-hardware/
- (stretch) https://www.bunniestudios.com/blog/2019/supply-chain-security-talk/
- https://www.forbes.com/sites/stevebanker/2023/02/17/the-worlds-most-vulnerable-supply-chain-impacts-all-supply-chains/
- https://www.ft.com/content/c02fbf55-ae33-427b-8302-56529f9d5719

Then, discuss with the following prompts:
1. What are the main bottlenecks in the supply chain for AI accelerators?
2. How could an adversary exploit these bottlenecks?
3. What has been the effect of the export controls? Now that they have been lifted, what do you expect to see? Were the expert controls a good idea?

### Exercise 1.2

Ask a TA for this exercise!

"""

"""
## Exercise 2: Model Context Protocol (MCP)

### Exercise 2.1: Writing a MCP Client

Let's start by implementing a simple MCP client that can connect to our MCP server at `https://0.mcp.aisb.dev`.

The documentation for MCP can be found at https://modelcontextprotocol.io/specification/
A couple of useful links:
- https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#streamable-http
- https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle

I recommend you do these in this order:
1. implement connect()
2. implement send_message() and get_message() methods to send and receive messages from the MCP server.
3. implement the handshake() method to initialize the connection with the MCP server.
4. implement get_resources() and get_tools() methods to list resources and tools available on the MCP server.
5. implement access_resource() method to access a specific resource by its URI.
6. implement access_tool() method to access a specific tool by its URI.

Using this, you can access the MCP servers and run custom commands to exploit the resources and tools available on the server.

"""

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
        if "SOLUTION":
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

        else:
            # todo: Implement the connection logic to the MCP server
            #   - Start by making a GET request to the MCP server's SSE endpoint and stream the response.
            #   - Parse the incoming lines to extract the messages
            #   - Store the endpoint URL in self.endpoint and push the messages to self.messages
            #   - Have a lower bar for looking at the solution for this one if you don't know how http streaming works
            pass

    def send_message(self, message):
        """
        Send a message to the MCP server.
        :param message: The message to send.
        :return: The response from the MCP server.
        """
        if not self.endpoint:
            raise ValueError("Endpoint is not set. Connect to the MCP server first.")

        if "SOLUTION":
            response = requests.post(self.url_base + self.endpoint, json=message)
            if not 200 <= response.status_code < 300:
                raise Exception(f"Failed to send message: {response.status_code} - {response.text}")

            return response.text
        else:
            # todo: send a message to the MCP server
            pass

    def get_message(self):
        """
        Get the latest message from the MCP server.
        :return: The latest message received from the MCP server.
        """
        if "SOLUTION":
            while len(self.messages) == 0:
                time.sleep(0.1)  # Wait for a message to be received
            return self.messages.pop(0)
        else:
            # todo: wait for a message to show up in the queue and return it
            pass

    def handshake(self):
        """
        Hansdshake with the MCP server to initialize the connection.
        """
        if not self.endpoint:
            raise ValueError("Endpoint is not set. Connect to the MCP server first.")

        if "SOLUTION":
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
        else:
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
        if "SOLUTION":
            message = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "resources/list",
                "params": {"cursor": cursor} if cursor else {},
            }
            self.send_message(message)
            response = self.get_message()
            return response.get("result", {}).get("resources", [])
        else:
            # todo: implement the logic to list resources on the MCP server
            pass

    def get_tools(self, cursor=None):
        """
        Get tools from the MCP server.
        :param cursor: Optional cursor for pagination.
        :return: List of tools.
        """
        if "SOLUTION":
            message = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"cursor": cursor}}
            self.send_message(message)
            response = self.get_message()
            return response.get("result", {}).get("tools", [])
        else:
            # todo: implement the logic to list tools on the MCP server
            pass

    def access_resource(self, resource_uri):
        """
        Access a specific resource by its URI.
        :param resource_uri: The URI of the resource to access.
        :return: The resource data.
        """

        if "SOLUTION":
            message = {"jsonrpc": "2.0", "id": 2, "method": "resources/read", "params": {"uri": resource_uri}}

            self.send_message(message)
            response = self.get_message()
            if "result" in response:
                return response
            elif "error" in response:
                raise Exception(f"Error accessing resource: {response['error']}")
            else:
                raise Exception("Unexpected response format: " + json.dumps(response))
        else:
            # todo: implement the logic to access a resource by its URI
            pass


if False:
    # Example usage
    mcp_client = MCPClient("https://0.mcp.aisb.dev")
    thread = threading.Thread(target=mcp_client.connect, daemon=True).start()
    while not mcp_client.endpoint:
        time.sleep(0.1)
        print(".", end="")
    mcp_client.handshake()

"""

### Exercise 2.1b: All the servers!

Once you have the flag for exercise 0, you can move to getting the flag for exercise 1 & 2. (https://1.mcp.aisb.dev and https://2.mcp.aisb.dev). These servers have more complex resources and tools that you can use to get the flag.

Continue updating your code to implement any remaining methods required to complete the CTF.

After completing exercise 1 & 2:
- You can move to exercise 2.2 and work on servers 0-2 using cline, then come back to this section for the remaining servers.
- Or, you can move to the next set of servers (https://3.mcp.aisb.dev thru https://9.mcp.aisb.dev)

### Exercise 2.2: Using Cline to interact with the MCP servers

Install (cline)[https://docs.cline.bot/getting-started/what-is-cline], which is a vscode extension that allows you to interact with MCP servers directly from your editor.

Once you have installed cline, you can use the following configuration to connect to the MCP server:
<summary>
<details>Connection Configuration</details>
```json
{
  "mcpServers": {
    "Challenge 1": {
      "disabled": false,
      "timeout": 60,
      "type": "stdio",
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://0.mcp.aisb.dev/sse"
      ]
    },
    "Challenge 2": {
      "disabled": false,
      "timeout": 60,
      "type": "stdio",
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://1.mcp.aisb.dev/sse"
      ]
    },
    "Challenge 3": {
      "disabled": false,
      "timeout": 60,
      "type": "stdio",
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://2.mcp.aisb.dev/sse"
      ]
    },
    "Challenge 4": {
      "disabled": false,
      "timeout": 60,
      "type": "stdio",
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://3.mcp.aisb.dev/sse"
      ]
    },
    "Challenge 5": {
      "disabled": false,
      "timeout": 60,
      "type": "stdio",
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://4.mcp.aisb.dev/sse"
      ]
    },
    "Challenge 6": {
      "disabled": false,
      "timeout": 60,
      "type": "stdio",
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://5.mcp.aisb.dev/sse"
      ]
    },
    "Challenge 7": {
      "disabled": false,
      "timeout": 60,
      "type": "stdio",
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://6.mcp.aisb.dev/sse"
      ]
    },
    "Challenge 8": {
      "disabled": false,
      "timeout": 60,
      "type": "stdio",
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://7.mcp.aisb.dev/sse"
      ]
    },
    "Challenge 9": {
      "disabled": false,
      "timeout": 60,
      "type": "stdio",
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://8.mcp.aisb.dev/sse"
      ]
    },
    "Challenge 10": {
      "disabled": false,
      "timeout": 60,
      "type": "stdio",
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://9.mcp.aisb.dev/sse"
      ]
    }
  }
}
```
</summary>

After this, you can try each challenge by trying to prompt the model. Use claude 3.5 haiku for this.

### Exercise 2.3: Securing MCP

Start by reading https://blog.trailofbits.com/2025/07/28/we-built-the-security-layer-mcp-always-needed/

You can try one of these optional exercises to secure the MCP server:
1. Implement the features as described in the article.
2. Implement Oauth authentication for the MCP server - https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
"""
