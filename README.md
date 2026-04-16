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
   Leverages standard standard I/O for instantaneous asynchronous message parsing. No hacky socket overhead delays.

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

---

## 💻 MCP Client Configuration

Because `unified-re-mcp` is universally compatible with standard `stdio`, you can configure any modern client frictionlessly.

### Example 1: Claude Desktop
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

### Example 2: Cline
In Cline, select `MCP Servers` at the top. Select `Command` as your integration type, and paste your `uv run` invocation exactly as written in the config output.

### Example 3: 5ire
Open 5ire and go to `Tools` -> `New` and set the following configurations:

1. Tool Key: `unified-re-mcp`
2. Name: UnifiedRE
3. Command: `uv run C:\ABSOLUTE_PATH_TO\unified-re-mcp\main.py`

---

## ⚙️ Standardized Core Operations 

The Unified MCP Server currently exposes several highly validated cross-backend tools directly to the agent. Below is a subset of operations currently supported:

| Tool Invocation | Description | Backend Support |
|---|---|---|
| `list_functions()` | Retrieve a paginated array of valid functions natively decoded from the binary to search. | IDA & Ghidra |
| `get_function_decompilation(addr)` | Safely generates and fetches C-pseudocode abstract syntax tree interpretations from Hex-Rays/Ghidra. | IDA & Ghidra |
| `get_function_xrefs(addr)` | Provides structured arrays of `xrefs_to` and `xrefs_from` dictating deep execution block flows. | IDA & Ghidra |
| `rename_symbol(addr, int, type)` | Pushes intelligent algorithmic renaming directly into the live IDE database safely. | IDA & Ghidra |
| `find_strings()` | Extracts mapped ASCII/UTF-8 datasegments dynamically for string analysis. | IDA & Ghidra |

---

## 🧠 Prompt Engineering

LLMs are prone to hallucinations, so precise prompting is critical. Below is a minimal, proven example prompt for use with our unified framework:

```md
Your task is to analyze a crackme binary. You can use the MCP tools to interact with my open IDA/Ghidra instance. Please strictly follow this systematic methodology:

1. **Decompilation Analysis**: Inspect the decompilation using `get_function_decompilation`, and analyze it carefully block-by-block. 
2. **Readability**: Rename variables using `rename_symbol` to sensible names based on algorithmic patterns. Change function names to describe their actual operational purpose.
3. **Deep Dives**: If more details are necessary, pull cross-references using `get_function_xrefs` to identify calling functions or examine the entry points.
4. **Constraints**: NEVER convert number bases yourself. NEVER assume compiler structures blindly. Derive all findings purely from tool data.
5. **Documentation**: Create a comprehensive markdown report listing execution flows you discovered.
```

## 🎯 Tips for Enhancing LLM Accuracy

Large Language Models (LLMs) are powerful heuristic pattern matchers, but they will struggle to bypass complex virtualization. To guarantee absolute accuracy, preprocess the binary:

- Eliminate basic control flow flattening
- Unwrap inline string encryption
- Unmap import hashing APIs
- Restore basic IDA function bounds before prompt submission

Furthermore, apply libraries like FLIRT or Lumina signatures. Replacing `sub_401100` with `std::string::append` eliminates hundreds of lines of noise from the LLM context, massively reducing operational errors.

---

## 🛠️ Extensibility & Development

Integrating additional tools into `unified-re-mcp` is intentionally frictionless. There is absolute zero traditional socket or routing boilerplate.

### Example: Adding a New Tool

Simply drop a new Python function explicitly decorated with `@mcp.tool()` inside `server.py`, fully type-hint the arguments, and you're done. 

```python
@mcp.tool()
async def read_memory_bytes(ctx: Context, address: int, size: int) -> bytes:
    """ Reads raw operative bytes directly from the database memory map. """
    session = await manager.get_session(ctx.session_id)
    return await session.adapter.read_memory(address, size)
```
The underlying `fastmcp` validator will autonomously detect the `address: int` and auto-generate the strict JSON-RPC payload interface schemas.

### Local Tool Testing
To independently debug or test the server without spinning up a live LLM chat:

```sh
npx -y @modelcontextprotocol/inspector uv run main.py
```
This runs a local web debugger where you can click buttons to instantly fire custom JSON test schemas directly at the server.
