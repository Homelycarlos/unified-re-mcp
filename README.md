# Unified Reverse Engineering MCP Server

A unified Model Context Protocol (MCP) server that seamlessly bridges both **IDA Pro** and **Ghidra** into a single, cohesive, AI-compatible interface. Designed with strict determinism and statelessness in mind, this project enables AI coding agents (like Claude Desktop and Antigravity) to perform automated, normalized reverse engineering tasks across different backends.

## Architecture Features
- **Pydantic Schema Enforcement**: All tool inputs and outputs are normalized to strict, predictable JSON-RPC 2.0 signatures regardless of whether they come from IDA or Ghidra.
- **Stateless Session Management**: Implements a `SessionManager` that isolates tool state via `session_id`, ensuring no global state leaks and high concurrency safety.
- **Asynchronous Execution (`FastMCP`)**: Built natively on top of `fastmcp` to ensure fast asynchronous command processing directly into Claude over stdio.

## Backends Supported

### IDA Pro 8.0+ / 9.x
This repository includes a background IDAPython listener plugin (`plugins/ida/ida_backend_plugin.py`).
- Safely bridges requests onto IDA's execution thread using `ida_kernwin.execute_sync`.
- Exposes critical reversing tools: `decompile_function`, `rename_symbol`, `get_xrefs`.
- Designed to run permanently as an IDA Plugin with `PLUGIN_FIX`.

### Ghidra
Integrates with standard GhidraMCP setups via background HTTP server adapter wrappers. 

## Requirements
- `uv` (recommended) or `python >= 3.10`
- `fastmcp`, `pydantic`, `aiohttp`

## Installation
Add the server configuration to your `claude_desktop_config.json` (or any compatible MCP client):

```json
"unified-reverse-engineering": {
  "command": "uv",
  "args": [
    "run",
    "--with", "mcp[cli]",
    "--with", "pydantic",
    "--with", "aiohttp",
    "C:\\Path\\To\\unified-re-mcp\\main.py"
  ]
}
```

## Running the IDA Plugin
1. Copy `plugins/ida/ida_backend_plugin.py` to your IDA Pro `plugins/` directory.
2. Launch IDA. The plugin automatically spawns a background thread on port `10101`.
3. Interact with your AI agent to decompile, rename, and automatically manipulate your IDA database without manually touching the UI.
