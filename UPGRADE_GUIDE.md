# Antigravity MCP Server Upgrade Guide

This guide will teach you how to upgrade an MCP Server in an Antigravity environment (e.g. Ghidra, IDA Pro, NexusRE, etc.) when they are configured locally in your AI Agent system.

## 1. Update the Server Files

First, fetch the updated version of the MCP server.

### For Ghidra MCP:
Download the latest release (e.g. from the GitHub repository), extract it, and replace your existing python server files.  
**Critical Step:** You must also install the newly generated `.zip` extension via the Ghidra UI (`File -> Install Extensions`) and restart Ghidra to sync the extension with the python server!

### For Python/UV Servers (like NexusRE / IDA):
Open a terminal in their respective folders and update your environment:
```bash
git pull
uv sync
```

## 2. Update the Configuration (If Needed)

If the execution paths change or require new arguments, you must update the configuration file in Antigravity so the agent knows how to start the tool server.  
Your MCP servers are registered in this file:
`%USERPROFILE%\.gemini\antigravity\mcp_config.json`

Example:
```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [ "C:\\path\\to\\new\\bridge_mcp_ghidra.py" ],
      "disabled": false
    }
  }
}
```

## 3. Restart Antigravity

Once the files and configuration are updated, the easiest way to load the new server capabilities is to simply restart the Antigravity chat environment or workspace. This triggers the agent to reconnect to the new server versions automatically using the JSON config.
