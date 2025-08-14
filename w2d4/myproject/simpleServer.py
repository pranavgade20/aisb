# simple_server.py
from http.server import HTTPServer, SimpleHTTPRequestHandler
import os

os.chdir("/workspaces/aisb/w2d4/myproject/templates")
server = HTTPServer(("0.0.0.0", 8001), SimpleHTTPRequestHandler)
print("Server running on http://localhost:8001")
server.serve_forever()
