import os
import sys
import json

# Ensure the root directory is accessible so modules resolve correctly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.server import mcp

def print_config():
    script_path = os.path.abspath(__file__)
    config = {
        "mcpServers": {
            "unified-reverse-engineering": {
                "command": "uv",
                "args": [
                    "run",
                    "--with", "mcp[cli]",
                    "--with", "pydantic",
                    "--with", "aiohttp",
                    script_path
                ]
            }
        }
    }
    
    print("=========================================")
    print(" UNIFIED MCP SERVER CONFIGURATION")
    print("=========================================\n")
    print("Copy the JSON block below and paste it into your MCP client's configuration file:")
    print(" - Claude Desktop: %APPDATA%\\Claude\\claude_desktop_config.json or ~/Library/Application Support/Claude/claude_desktop_config.json")
    print(" - Cursor / Roo Code / Cline: Add to your MCP settings or workspace mcp.json")
    print(" - Windsurf / Trae: Follow standard MCP initialization paths.\n")
    print(json.dumps(config, indent=2))
    print("\n=========================================")
    sys.exit(0)

if __name__ == "__main__":
    if "--config" in sys.argv:
        print_config()
        
    # Start the fastMCP server via standard CLI execution
    mcp.run()
