[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/Homelycarlos/unified-re-mcp)](https://github.com/Homelycarlos/unified-re-mcp/releases)
[![GitHub stars](https://img.shields.io/github/stars/Homelycarlos/unified-re-mcp)](https://github.com/Homelycarlos/unified-re-mcp/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/Homelycarlos/unified-re-mcp)](https://github.com/Homelycarlos/unified-re-mcp/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/Homelycarlos/unified-re-mcp)](https://github.com/Homelycarlos/unified-re-mcp/graphs/contributors)
[![Follow @lauriewired](https://img.shields.io/twitter/follow/lauriewired?style=social)](https://twitter.com/lauriewired)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)

# Unified Reverse Engineering MCP Server

Simple [MCP Server](https://modelcontextprotocol.io/introduction) to allow vibe reversing in both **IDA Pro** and **Ghidra** using a unified, stateless interface.

The binaries and dataset prompts for testing are compatible with standard prompt-engineering reversing methodology.

https://github.com/user-attachments/assets/36080514-f227-44bd-af84-78e29ee1d7f9

## Prerequisites

- [Python](https://www.python.org/downloads/) (**3.11 or higher**)
  - Use `idapyswitch` to bind IDA to your newest Python version if necessary.
- [uv](https://docs.astral.sh/uv/) (highly recommended for automatic, sandboxed dependency execution)
- [IDA Pro](https://hex-rays.com/ida-pro) (8.3 or higher, 9.x recommended), **IDA Free is not supported**
- Ghidra + [GhidraMCP Plugin](https://github.com/LaurieWired/GhidraMCP/releases) *(If using the Ghidra backend)*
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
  - [Other MCP Clients](https://modelcontextprotocol.io/clients#example-clients): Run `uv run main.py --config` to get the JSON config string.

## Installation

Clone this repository to your local machine:

```sh
git clone https://github.com/Homelycarlos/unified-re-mcp.git
cd unified-re-mcp
```

Generate the exact configuration block for your MCP Client (like Cursor or Claude) by running:

```sh
uv run main.py --config
```

### 1. IDA Pro Configuration
To allow the server to securely interact directly with your open database:
1. Copy `plugins/ida/ida_backend_plugin.py` directly into your IDA Pro `plugins/` directory.
2. Launch IDA Pro. 

### 2. Ghidra Configuration
First, download the latest [release](https://github.com/LaurieWired/GhidraMCP/releases) from the GhidraMCP repository. Then, securely import the plugin into Ghidra.

1. Run Ghidra
2. Select `File` -> `Install Extensions`
3. Click the `+` button
4. Select the `GhidraMCP-1-x.zip` from the downloaded release
5. Restart Ghidra
6. Make sure the GhidraMCPPlugin is enabled in `File` -> `Configure` -> `Developer`

Video Installation Guide:

https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3

---

## Example 1: Claude Desktop
To set up Claude Desktop as an MCP client, go to `Claude` -> `Settings` -> `Developer` -> `Edit Config` -> `claude_desktop_config.json` and add the config generated from `uv run main.py --config`.

Alternatively, edit this file directly:
```
%APPDATA%\Claude\claude_desktop_config.json
```

**Important**: Make sure you completely restart your MCP client for the configuration to take effect. Some clients (like Claude Desktop) run in the background and must be explicitly quit from the tray icon.

## Example 2: Cline
To use this with [Cline](https://cline.bot), go to the MCP servers panel at the top of your chat window.
Select `Command`, and paste your `uv run` invocation exactly as written in the config output.
![Cline select](https://github.com/user-attachments/assets/88e1f336-4729-46ee-9b81-53271e9c0ce0)

## Example 3: 5ire
Another MCP client that supports multiple models on the backend is [5ire](https://github.com/nanbingxyz/5ire). To set up the unified MCP, open 5ire and go to `Tools` -> `New` and set the following configurations:

1. Tool Key: `unified-re-mcp`
2. Name: UnifiedRE
3. Command: `uv run /ABSOLUTE_PATH_TO/main.py`

---

## Prompt Engineering

LLMs are prone to hallucinations and you need to be specific with your prompting. For reverse engineering, context management is crucial. Below is a minimal example prompt:

```md
Your task is to analyze a binary in IDA Pro/Ghidra using the MCP tools. In general, use the following strategy:

- Inspect the decompilation and analyze it carefully. 
- Rename variables to more sensible names based on algorithmic patterns.
- Change function names to describe their actual purpose within the binary.
- If more details are necessary, pull cross-references to identify calling functions.
- Create a report with your findings.
- NEVER assume conclusions blindly. Derive all findings from actual analysis using MCP tools.
```

## Tips for Enhancing LLM Accuracy

Large Language Models (LLMs) are powerful tools, but they will not perform well on heavily obfuscated code. Before handing the database over to the LLM agent, take a look around the binary and spend some time removing:

- String encryption
- Import hashing
- Control flow flattening
- Anti-decompilation tricks

You should also use tools like Lumina or FLIRT to resolve open-source library code (like the C++ STL). This enormously reduces the token count sent to the LLM and improves context accuracy.

## Core Capabilities

Because this server implements the standard MCP JSON-RPC protocol asynchronously over `stdio`, it exposes universal access to:

- **Detailed Decompilation**: Pull C-pseudocode directly from Hex-Rays or Ghidra.
- **Intelligent Renaming**: Update global variables, locals, and function symbol tables dynamically.
- **Cross-Referencing**: Fast querying of `xrefs_to` and `xrefs_from` to map executable flows.
- **Backend Portability**: The same MCP command set transparently maps between both IDA and Ghidra environments depending on your chosen adapter.

## Comparison with other MCP servers

There are a few IDA Pro MCP servers floating around, but we created the Unified Reverse Engineering Server for a few distinct reasons:

1. **Stateless execution model**: `SessionManager` ensures perfect async handling and environment separation.
2. **Pydantic Validation**: Impossible to pass malformed arguments to the engine; everything is validated via JSON Schema automatically generated and sent to the LLM. 
3. **Multi-Backend**: Supports both IDA Pro and Ghidra seamlessly without modifying the AI agent's core prompts or tool-calling behavior.

## Development

Adding new features is exceptionally streamlined thanks to `fastmcp`. Simply drop a Python function decorated with `@mcp.tool()` into `server.py`, strictly type-hint its arguments, and you are done. The Pydantic validator handles JSON-schema generation and argument routing automatically.

To test the MCP server independently without an AI agent:

```sh
npx -y @modelcontextprotocol/inspector uv run main.py
```

### Building Ghidra Dependencies from Source
If modifying the core Ghidra adapter, you may need to rebuild it manually.
1. Copy the core `Ghidra` `.jar` files to `lib/`.
2. Build with Maven by running: `mvn clean package assembly:single`
