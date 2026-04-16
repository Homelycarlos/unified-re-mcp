import os
import sys

# Ensure the root directory is accessible so modules resolve correctly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.server import mcp

if __name__ == "__main__":
    # Start the fastMCP server via standard CLI execution
    mcp.run()
