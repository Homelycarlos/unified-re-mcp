# ⚡ Unified Reverse Engineering MCP Server

A powerful, stateless Model Context Protocol (MCP) server that seamlessly bridges **IDA Pro** and **Ghidra** into a single, cohesive AI-driven reverse engineering environment.

Designed from the ground up for strict determinism, thread-safety, and seamless integration with modern AI coding agents, this server allows your AI assistants to automatically decompile functions, rename symbols, and fetch cross-references without you ever needing to touch the IDA/Ghidra UI.

---

## 🌟 Key Features

* **Universal Support**: Works out of the box with over 20+ AI clients including **Claude Desktop, Cursor, Roo Code, Windsurf, Trae, Gemini CLI**, and more.
* **Pydantic Schema Enforcement**: All tool inputs and outputs are automatically normalized into strict, predictable JSON-RPC 2.0 signatures regardless of whether they originate from IDA or Ghidra.
* **Stateless Session Management**: A built-in `SessionManager` isolates tool states via unique `session_id` identifiers, completely eliminating global state leaks and enabling high concurrency safety.
* **Asynchronous Execution**: Native integration with `FastMCP` ensures highly responsive asynchronous processing directly over standard `stdio`.

## 🔧 Supported Backends

### 1. IDA Pro (8.0+ / 9.x)
Includes a fully native background IDAPython listener plugin (`plugins/ida/ida_backend_plugin.py`).
- Safely routes external requests onto IDA's strict main execution thread using `ida_kernwin.execute_sync` to prevent database corruption.
- Runs permanently as a background daemon whenever IDA is open, requiring zero manual script execution (`PLUGIN_FIX`).

### 2. Ghidra
Integrates with standard Ghidra HTTP server adapter wrappers, providing the identical MCP tool interface for seamless backend switching and comparative analysis.

---

## 🛠️ Installation & Setup

### Prerequisites
* Python (3.11 or higher) — *Use `idapyswitch` to bind IDA to your newest Python version if necessary.*
* [uv](https://docs.astral.sh/uv/) (highly recommended for automatic, sandboxed dependency execution)
* IDA Pro (8.3 or higher, 9.x recommended). *Note: IDA Free is not supported as it lacks IDAPython.*

### Supported MCP Clients
Because this framework implements the strict MCP JSON-RPC standard over standard I/O, it inherently works with all major AI coding assistants. Pick the one you like:

* Amazon Q Developer CLI
* Augment Code
* Claude
* Claude Code
* Cline
* Codex
* Copilot CLI
* Crush
* Cursor
* Gemini CLI
* Kilo Code
* Kiro
* LM Studio
* Opencode
* Qodo Gen
* Qwen Coder
* Roo Code
* Trae
* VS Code
* VS Code Insiders
* Warp
* Windsurf
* Zed

**Other MCP Clients:** Just run `uv run main.py --config` to generate the correct JSON configuration for your specific client!

### 1. Configure Your MCP Client
To automatically generate the exact JSON configuration needed for your specific AI client, simply run:

```bash
uv run main.py --config
```

Copy the resulting block and paste it into your client's settings.

**Quick locations for popular clients:**
* **Claude Desktop:** `%APPDATA%\Claude\claude_desktop_config.json`
* **Cursor / Windsurf / Roo Code:** Add via the IDE's MCP server panel or local workspace `mcp.json`.

### 2. Install the IDA Plugin
For the IDA Pro integration to function:
1. Copy the file `plugins/ida/ida_backend_plugin.py` to your IDA Pro `plugins/` directory.
   *(Example Windows path: `C:\IDA Professional 9.1\plugins\`)*
2. Launch IDA Pro. 
3. The plugin will automatically spawn a lightweight background listener on `127.0.0.1:10101`.

---

## 💻 Usage Example

Once connected, simply ask your AI agent:
> *"What functions call the `malloc` wrapper in my open IDA database? Decompile them, analyze what they do, and rename them based on your findings."*

The agent will autonomously connect to the IDA backend adapter, pull all cross-references, analyze the C pseudo-code, and push the new symbol names directly into your live IDA GUI!

---
*Built aggressively with FastMCP and Pydantic.*
