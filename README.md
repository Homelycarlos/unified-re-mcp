[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/Homelycarlos/unified-re-mcp)](https://github.com/Homelycarlos/unified-re-mcp/releases)
[![GitHub stars](https://img.shields.io/github/stars/Homelycarlos/unified-re-mcp)](https://github.com/Homelycarlos/unified-re-mcp/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/Homelycarlos/unified-re-mcp)](https://github.com/Homelycarlos/unified-re-mcp/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/Homelycarlos/unified-re-mcp)](https://github.com/Homelycarlos/unified-re-mcp/graphs/contributors)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)

# Unified Reverse Engineering MCP Server

Simple [MCP Server](https://modelcontextprotocol.io/introduction) to allow vibe reversing in IDA Pro and Ghidra.

https://github.com/user-attachments/assets/6ebeaa92-a9db-43fa-b756-eececce2aca0

The binaries and prompt for the video are available in the [mcp-reversing-dataset](https://github.com/mrexodia/mcp-reversing-dataset) repository.

## Features

- Decompile and analyze binaries in Ghidra and IDA Pro
- Automatically rename methods and data
- List methods, classes, imports, and exports

## Prerequisites

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

## Installation

Install the latest version of the Unified MCP Server:

```sh
git clone https://github.com/Homelycarlos/unified-re-mcp.git
cd unified-re-mcp
```

### IDA Pro Integration
1. Copy `plugins/ida/ida_backend_plugin.py` to your IDA Pro `plugins/` directory.
2. Launch IDA Pro. 

### Ghidra Integration
1. Select `File` -> `Install Extensions`
2. Click the `+` button
3. Select the `GhidraMCP-1-x.zip` release
4. Restart Ghidra
5. Make sure the GhidraMCPPlugin is enabled in `File` -> `Configure` -> `Developer`

Video Installation Guide:

https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3

## MCP Clients

Theoretically, any MCP client should work. Three examples are given below.

### Example 1: Claude Desktop
To set up Claude Desktop, go to `Claude` -> `Settings` -> `Developer` -> `Edit Config` -> `claude_desktop_config.json` and add the following:

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
        "C:\\ABSOLUTE_PATH\\TO\\main.py"
      ]
    }
  }
}
```

Alternatively, edit this file directly: `%APPDATA%\Claude\claude_desktop_config.json`

**Important**: Make sure you completely restart your MCP client for the configuration to take effect.

### Example 2: Cline
In Cline, select `MCP Servers` at the top. Select `Command` and paste your `uv run` invocation.

![Cline select](https://github.com/user-attachments/assets/88e1f336-4729-46ee-9b81-53271e9c0ce0)

### Example 3: 5ire
Open 5ire and go to `Tools` -> `New` and set the following configurations:

1. Tool Key: unified-re-mcp
2. Name: UnifiedRE
3. Command: `uv run C:\ABSOLUTE_PATH_TO\main.py`

## Prompt Engineering

LLMs are prone to hallucinations and you need to be specific with your prompting. Below is a minimal example prompt:

```md
Your task is to analyze a crackme in IDA Pro/Ghidra. You can use the MCP tools to retrieve information. In general use the following strategy:

- Inspect the decompilation and add comments with your findings
- Rename variables to more sensible names
- Change the variable and argument types if necessary
- Change function names to be more descriptive
- If more details are necessary, disassemble the function and add comments
- NEVER convert number bases yourself. Use MCP tools if needed!
- Do not attempt brute forcing, derive any solutions purely from the disassembly
- Create a report.md with your findings
```

## Tips for Enhancing LLM Accuracy

Large Language Models (LLMs) are powerful tools, but they can sometimes struggle. Another thing to keep in mind is that LLMs will not perform well on obfuscated code. Spend some time removing:

- String encryption
- Import hashing
- Control flow flattening
- Anti-decompilation tricks

You should also use a tool like Lumina or FLIRT to try and resolve all the open source library code and the C++ STL, this will further improve the accuracy.

## Core Operations

- `lookup_funcs(queries)`: Get function(s) by address or name.
- `int_convert(inputs)`: Convert numbers to different formats.
- `decompile(addr)`: Decompile function at the given address.
- `xrefs_to(addrs)`: Get all cross-references to address(es).
- `analyze_funcs(addrs)`: Comprehensive function analysis.

## Comparison with other MCP servers

There are a few MCP servers floating around, but I created my own for a few reasons:

1. Installation should be fully automated.
2. The architecture makes it easy to add new functionality without too much boilerplate.
3. Learning new technologies is fun!

## Development

Adding new features is a super easy and streamlined process. All you have to do is add a new `@mcp.tool()` function.

To test the MCP server itself:

```sh
npx -y @modelcontextprotocol/inspector uv run main.py
```

### Building Ghidra Dependencies from Source
1. Copy the following files from your Ghidra directory to `lib/`:
- `Base.jar`, `Decompiler.jar`, `Docking.jar`, `Generic.jar`, `Project.jar`, `SoftwareModeling.jar`, `Utility.jar`, `Gui.jar`
2. Build with Maven by running:

`mvn clean package assembly:single`
