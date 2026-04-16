[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/Homelycarlos/unified-re-mcp)](https://github.com/Homelycarlos/unified-re-mcp/releases)
[![GitHub stars](https://img.shields.io/github/stars/Homelycarlos/unified-re-mcp)](https://github.com/Homelycarlos/unified-re-mcp/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/Homelycarlos/unified-re-mcp)](https://github.com/Homelycarlos/unified-re-mcp/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/Homelycarlos/unified-re-mcp)](https://github.com/Homelycarlos/unified-re-mcp/graphs/contributors)

# ⚡ Unified Reverse Engineering MCP Server

The **Unified Reverse Engineering MCP Server** is an enterprise-grade, stateless [Model Context Protocol](https://modelcontextprotocol.io/) framework that securely bridges **IDA Pro** and **Ghidra** into a single, cohesive AI-driven reverse engineering environment.

Designed from the ground up to prevent global state leaks and enforce strict typing, this server enables AI coding agents to autonomously navigate binaries, decompile functions, intelligently rename symbols, and fetch complex cross-references over `stdio` without requiring any manual UI interaction.

---

## 🌟 Core Architecture & Features

This project was built to address the boilerplate, unvalidated inputs, and state leakage issues of older standalone MCP plugins:

1. **Stateless Session Management (`SessionManager`)**: 
   When an AI agent connects, it requests a `session_id`. All subsequent actions are securely sandboxed to that session. This enables multiple agents, or multiple instances of an agent, to safely analyze entirely different binaries across different backends simultaneously without state interference.
2. **Pydantic Tool Validation**: 
   It is fundamentally impossible to pass malformed arguments to the engine. All inputs and outputs are automatically marshaled into strict JSON-RPC 2.0 schemas. If an AI hallucinates an argument format, it will receive an immediate descriptive Pydantic feedback error rather than crashing the Hex-Rays decompiler.
3. **Multi-Backend API Simplicity**:
   A single, unified Python `BaseAdapter` abstraction governs both Ghidra and IDA. You can write one AI prompt, securely use one client workflow, and hot-swap between an IDA Pro database and a Ghidra dataset frictionlessly depending on the target.
4. **FastMCP Integration**: 
   Leverages standard I/O and SSE for instantaneous asynchronous message parsing. No hacky socket overhead delays.

---

## 🛠️ Prerequisites

- [Python](https://www.python.org/downloads/) (**3.11 or higher**)
  - Use `idapyswitch` to switch to the newest Python version
- [IDA Pro](https://hex-rays.com/ida-pro) (8.3 or higher, 9 recommended), **IDA Free is not supported**
- Supported MCP Client (pick one you like)
  - [Amazon Q Developer CLI](https://aws.amazon.com/q/developer/)
  - [Augment Code](https://www.augmentcode.com/)
  - [Claude](https://claude.ai/download) & [Claude Code](https://www.anthropic.com/code)
  - [Cline](https://cline.bot)
  - [Codex](https://github.com/openai/codex)
  - [Copilot CLI](https://docs.github.com/en/copilot)
  - [Crush](https://github.com/charmbracelet/crush)
  - [Cursor](https://cursor.com)
  - [Gemini CLI](https://google-gemini.github.io/gemini-cli/)
  - [Kilo Code](https://www.kilocode.com/)
  - [Kiro](https://kiro.dev/)
  - [LM Studio](https://lmstudio.ai/)
  - [Opencode](https://opencode.ai/)
  - [Qodo Gen](https://www.qodo.ai/)
  - [Qwen Coder](https://qwenlm.github.io/qwen-code-docs/)
  - [Roo Code](https://roocode.com)
  - [Trae](https://trae.ai/)
  - [VS Code](https://code.visualstudio.com/) & [Insiders](https://code.visualstudio.com/insiders)
  - [Warp](https://www.warp.dev/)
  - [Windsurf](https://windsurf.com)
  - [Zed](https://zed.dev/)
  - [Other MCP Clients](https://modelcontextprotocol.io/clients#example-clients): Run `uv run main.py --config` to get the JSON config.

---

## 🚀 Installation & Integration

Install the latest version of the Unified MCP Server by cloning this repository:

```sh
git clone https://github.com/Homelycarlos/unified-re-mcp.git
cd unified-re-mcp
```

### 1. IDA Pro Integration
For the server to securely interact with your IDA instance natively:
1. Copy `plugins/ida/ida_backend_plugin.py` to your IDA Pro `plugins/` directory.
2. Launch IDA Pro. 
3. The plugin will execute via `PLUGIN_FIX` and spin up an isolated background HTTP listener automatically bound to IDA's execution thread (`ida_kernwin.execute_sync`) to prevent database corruption.

### 2. Ghidra Integration
The unified MCP server supports dispatching structural queries directly to existing Ghidra HTTP server plugin installations. You must have a compatible background listener running in Ghidra for the `ghidra` adapter to forward parameters successfully.

### 3. Automatic Client Installation (Recommended)
Instead of manually editing JSON config files, you can run the auto-installer which will detect Claude Desktop and Cursor on your system and inject the server config automatically:

```sh
uv run main.py --install
```

This will:
- Scan for Claude Desktop config files (including Windows Store UWP paths)
- Scan for Cursor global MCP storage
- Inject or update the `unified-reverse-engineering` server block
- Preserve any existing MCP server configurations you already have

---

## 💻 MCP Client Configuration

Because `unified-re-mcp` is universally compatible with standard `stdio`, you can configure any modern client frictionlessly.

### Automatic Setup
```sh
uv run main.py --install    # Auto-detect Claude/Cursor and inject config
```

### Manual Setup
Run `uv run main.py --config` to generate your exact path config, or add the following to `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "unified-re-mcp": {
      "command": "uv",
      "args": [
        "run",
        "--with", "mcp[cli]",
        "--with", "pydantic",
        "--with", "aiohttp",
        "C:\\ABSOLUTE_PATH\\TO\\unified-re-mcp\\main.py"
      ]
    }
  }
}
```
**Important**: Make sure you completely restart Claude from the system tray for the configuration to take effect.

### SSE / HTTP Transport
For browser-based AI models or remote agents, you can start the server with SSE (Server-Sent Events) transport instead of stdio:

```sh
uv run main.py --transport sse --port 8080
```

This launches a local HTTP server that accepts SSE connections, allowing any HTTP-capable AI client to query your IDA/Ghidra databases remotely.

---

## 🔌 Full Integration Guide

The Unified MCP Server is designed to work with every major AI coding environment, agent framework, and reverse engineering tool. Below is a complete guide on how to connect each one.

### 🧠 AI IDEs & Coding Agents

#### 1. Cursor IDE
Cursor has native MCP support. Go to `Settings` → `MCP` → `Add Server`:

```json
{
  "unified-re-mcp": {
    "command": "uv",
    "args": ["run", "--with", "mcp[cli]", "--with", "pydantic", "--with", "aiohttp", "C:\\PATH\\TO\\main.py"]
  }
}
```

Or run `uv run main.py --install` to auto-inject.

#### 2. VS Code (with Continue.dev)
Install the [Continue](https://continue.dev/) extension, then edit your `~/.continue/config.json`:

```json
{
  "mcpServers": [
    {
      "name": "unified-re-mcp",
      "command": "uv",
      "args": ["run", "--with", "mcp[cli]", "--with", "pydantic", "--with", "aiohttp", "C:\\PATH\\TO\\main.py"]
    }
  ]
}
```

This gives VS Code full MCP tool access for IDA/Ghidra queries directly in your editor.

#### 3. Windsurf (Codeium)
Windsurf supports MCP tool servers via its agent cascade system. Add to your Windsurf MCP configuration:

```json
{
  "mcpServers": {
    "unified-re-mcp": {
      "command": "uv",
      "args": ["run", "--with", "mcp[cli]", "--with", "pydantic", "--with", "aiohttp", "C:\\PATH\\TO\\main.py"]
    }
  }
}
```

#### 4. Continue.dev (VS Code / JetBrains)
Continue is fully MCP-compatible. Define the server as an external tool in your Continue config. It will appear as a callable tool alongside your LLM chat, perfect for querying decompiled functions mid-conversation.

---

### 🤖 Agent Frameworks

For maximum flexibility — chaining IDA + Ghidra + custom tools in automated pipelines — start the server in SSE mode first:

```sh
uv run main.py --transport sse --port 8080
```

#### 5. LangChain
Wrap the MCP server as a LangChain `Tool`:

```python
from langchain.tools import Tool
import requests

def call_mcp(action, args):
    return requests.post("http://localhost:8080/rpc", json={"action": action, "args": args}).json()

decompile_tool = Tool(
    name="decompile_function",
    description="Decompile a function at the given hex address using IDA/Ghidra",
    func=lambda addr: call_mcp("decompile", {"address": addr})
)
```

#### 6. LangGraph
LangGraph excels at multi-step reasoning. Define each MCP tool as a node in your graph, enabling the agent to autonomously chain `list_functions → decompile → get_xrefs → rename_symbol` flows.

#### 7. LlamaIndex
Connect as a tool connector in LlamaIndex's `FunctionTool` system:

```python
from llama_index.core.tools import FunctionTool

def decompile(address: str) -> str:
    """Decompile function at address via unified MCP server."""
    import requests
    r = requests.post("http://localhost:8080/rpc", json={"action": "decompile", "args": {"address": address}})
    return r.json().get("code", "")

tool = FunctionTool.from_defaults(fn=decompile)
```

#### 8. AutoGen (Microsoft)
Expose MCP tools to AutoGen multi-agent conversations:

```python
@user_proxy.register_for_execution()
@assistant.register_for_llm(description="Decompile a binary function")
def decompile_function(address: str) -> str:
    import requests
    return requests.post("http://localhost:8080/rpc",
        json={"action": "decompile", "args": {"address": address}}).text
```

#### 9. CrewAI
Create a CrewAI tool wrapper:

```python
from crewai_tools import BaseTool

class DecompileTool(BaseTool):
    name: str = "Decompile Function"
    description: str = "Decompiles a function at the given address using IDA/Ghidra MCP server"

    def _run(self, address: str) -> str:
        import requests
        r = requests.post("http://localhost:8080/rpc",
            json={"action": "decompile", "args": {"address": address}})
        return r.json().get("code", "")
```

---

### 🧩 Reverse Engineering & Security Tooling

#### 10. IDA Pro
The primary backend. Copy `plugins/ida/ida_backend_plugin.py` to your IDA `plugins/` folder. It will auto-start a background HTTP listener on port `10101` via `PLUGIN_FIX`. The MCP server dispatches all tool calls to this listener.

#### 11. Ghidra
The secondary backend. Install a compatible Ghidra HTTP bridge plugin (such as [GhidraMCP](https://github.com/LaurieWired/GhidraMCP)), then point the unified server's session to it using `backend="ghidra"`.

#### 12. Binary Ninja
No official MCP adapter exists, but you can build a custom bridge using Binary Ninja's Python API. Expose the same HTTP action interface that `ida_backend_plugin.py` uses, and point a session at it with a custom `backend_url`.

---

### 🧪 AI Chat & Model Platforms

#### 13. OpenAI API (Function Calling)
Use OpenAI's tool/function calling with SSE transport:

```python
tools = [{
    "type": "function",
    "function": {
        "name": "decompile_function",
        "description": "Decompile a binary function at the given hex address",
        "parameters": {
            "type": "object",
            "properties": {"address": {"type": "string"}},
            "required": ["address"]
        }
    }
}]
# When the model calls the tool, forward to: POST http://localhost:8080/rpc
```

#### 14. Anthropic Claude (API / Tool Use)
Claude's tool-use API maps perfectly to MCP:

```python
tools = [{
    "name": "decompile_function",
    "description": "Decompile a function at the given address via IDA/Ghidra.",
    "input_schema": {
        "type": "object",
        "properties": {"address": {"type": "string", "description": "Hex address"}},
        "required": ["address"]
    }
}]
# Route tool results back through the SSE endpoint
```

---

### ⚙️ Experimental / Self-Hosted AI UIs

#### 15. OpenDevin / Devin-style Agents
Open-source Devin variants are designed for tool execution and environment access. Configure the MCP server as an external tool endpoint. The agent can autonomously call `decompile_function`, `get_xrefs`, and `rename_symbol` as part of its reasoning loop.

#### 16. Open Interpreter
Open Interpreter can call external tools and scripts natively. Start the server in SSE mode and point Open Interpreter's tool config at `http://localhost:8080`.

---

## ⚙️ Standardized Core Operations 

The Unified MCP Server exposes **16 heavily validated cross-backend tools** directly to the AI agent. These functions are mapped identically across both IDA and Ghidra, meaning an agent can write a script once and leverage it on either backend.

### Decompilation & Disassembly
- `decompile_function(address)`: Safely pulls raw C pseudocode from either Hex-Rays or Ghidra decompilers.
- `disassemble_at(address)`: Disassembles the function block-by-block with full operand extraction detail. Returns structured `InstructionSchema` objects.
- `list_functions()`: Retrieves a paginated array of all valid functions natively identified in the executable.
- `get_function(address)`: Get complete details for a specific function by address.
- `batch_decompile(addresses)`: Decompile multiple functions in a single call for bulk analysis workflows.

### Control Flow & Cross-Reference Engine
- `get_xrefs(address)`: Automatically pulls cross-reference mappings (`xrefs_to`, `xrefs_from`) for deep execution flow analysis.

### Modification & Refactoring Operations
- `rename_symbol(address, new_name)`: Pushes intelligent algorithmic renaming directly into the live IDE database, managed asynchronously on the primary UI thread to prevent corruption.
- `set_comment(address, comment, repeatable)`: Places contextual comments dynamically in the disassembly or decompiler views for your AI to document its own progress.
- `set_function_type(address, signature)`: Applies complex C function prototypes to accurately sync argument states (e.g., `int __fastcall foo(int a1, char *a2)`).

### Data & String Analysis
- `get_strings()`: Extracts mapped ASCII/UTF-8 datasegments dynamically for string analysis and encryption detection.
- `get_globals()`: Iterates through the data sections to extract named global constants and variables.
- `get_segments()`: Returns all memory segments (`.text`, `.data`, `.rdata`, `.bss`) with start/end addresses, sizes, and permissions.
- `get_imports()`: Lists every imported symbol with its module origin (e.g., `kernel32.dll::VirtualProtect`).
- `get_exports()`: Lists every exported symbol from the binary.

---

## 🧠 Prompt Engineering

LLMs are prone to hallucinations, so precise prompting is critical. Below is a minimal, proven example prompt for use with our unified framework:

```md
Your task is to analyze a crackme binary. You can use the MCP tools to interact with my open IDA/Ghidra instance. Please strictly follow this systematic methodology:

1. **Decompilation Analysis**: Inspect the decompilation using `decompile_function`, and analyze it carefully block-by-block. 
2. **Readability**: Rename variables using `rename_symbol` to sensible names based on algorithmic patterns. Change function names to describe their actual operational purpose.
3. **Deep Dives**: If more details are necessary, pull cross-references using `get_xrefs` to identify calling functions or examine the entry points.
4. **Constraints**: NEVER convert number bases yourself. NEVER assume compiler structures blindly. Derive all findings purely from tool data.
5. **Documentation**: Create a comprehensive markdown report listing execution flows you discovered.
```

For a complete, battle-tested master prompt, see [AGENTS.md](AGENTS.md).

## 🎯 Tips for Enhancing LLM Accuracy

Large Language Models (LLMs) are powerful heuristic pattern matchers, but they will struggle to bypass complex virtualization. To guarantee absolute accuracy, preprocess the binary:

- Eliminate basic control flow flattening
- Unwrap inline string encryption
- Unmap import hashing APIs
- Restore basic IDA function bounds before prompt submission

Furthermore, apply libraries like FLIRT or Lumina signatures. Replacing `sub_401100` with `std::string::append` eliminates hundreds of lines of noise from the LLM context, massively reducing operational errors.

---

## 🛠️ Extensibility & Development

Integrating additional tools into `unified-re-mcp` is intentionally frictionless. There is absolutely zero traditional socket or routing boilerplate.

### Example: Adding a New Tool

Simply drop a new Python function explicitly decorated with `@mcp.tool()` inside `server.py`, fully type-hint the arguments, and you're done. 

```python
@mcp.tool()
async def read_memory_bytes(session_id: str, address: str, size: int) -> Any:
    """ Reads raw operative bytes directly from the database memory map. """
    adapter = get_adapter(session_id)
    return await adapter.read_memory(address, size)
```
The underlying `fastmcp` validator will autonomously detect the `address: str` and auto-generate the strict JSON-RPC payload interface schemas.

### CLI Reference

```
uv run main.py                 Start the MCP server (stdio transport)
uv run main.py --config        Print the JSON config for manual setup
uv run main.py --install       Auto-detect & inject config into Claude/Cursor
uv run main.py --transport sse Start the server with SSE transport (HTTP)
uv run main.py --port 8080     Set the SSE server port (default: 8080)
uv run main.py --help          Show help message
```

### Local Tool Testing
To independently debug or test the server without spinning up a live LLM chat:

```sh
npx -y @modelcontextprotocol/inspector uv run main.py
```
This runs a local web debugger where you can click buttons to instantly fire custom JSON test schemas directly at the server.
