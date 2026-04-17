<br/>
<div align="center">

# ⚡ NexusRE MCP
**The Universal AI Bridge for Game Hacking & Reverse Engineering**

[![PyPI version](https://badge.fury.io/py/nexusre-mcp.svg)](https://badge.fury.io/py/nexusre-mcp)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Discord](https://img.shields.io/discord/1234567890?label=Discord&logo=discord&color=5865F2)](https://discord.gg/nexusre)

[Features](#-killer-features) • [Installation](#-installation) • [Dashboard](#-cyberpunk-dashboard) • [Supported Backends](#-supported-backends)

</div>

**NexusRE** is an Enterprise-grade Model Context Protocol (MCP) server that connects your AI assistants (Cursor, Claude, Windsurf) directly to your reverse engineering environments. 

Instead of writing isolated scripts for IDA, x64dbg, or Cheat Engine, NexusRE acts as a universal adapter. You can highlight a piece of C++ SDK code in Cursor and say, *"Check my live x64dbg session to see what the register value is here,"* and the AI will do exactly that.

---

## 🔥 Killer Features

### 1. 🤖 AI Auto-Signature Recovery
Game updated? Say goodbye to spending 4 hours in IDA fixing broken offsets. 
NexusRE tracks your memory signatures in its persistent **Brain DB**. When a patch drops, the MCP automatically diffs the dead signatures, analyzes cross-references in the new binary, and generates fixed patterns instantly. 

```python
# AI automatically triggers this when offsets break
auto_recover_signatures(session_id="ida_master", game="r6siege")
```

### 2. 🔀 Multi-Backend Cross-Analysis
Connect Claude to **IDA Pro (Static)** and **x64dbg (Dynamic)** simultaneously. The AI can pull the decompiled C pseudocode from IDA, while fetching the live runtime memory and register state from x64dbg at the exact same address.

### 3. 👻 Undetected DMA Hardware Support
NexusRE supports physical PCIe DMA cards (PCILeech/Raptor). With standard Cheat Engine tools, Ring-0 Anti-Cheats (EAC, Vanguard) will ban you. With the `dma` backend, the AI executes 100% undetected physical memory reads/writes straight over the motherboard's electrical bus.

---

## 💻 Cyberpunk Dashboard

NexusRE comes with a gorgeous, real-time React Web Dashboard and a built-in Discord Bot daemon.

* **Live Polling:** Watch your active sessions blink green/red in real-time.
* **Signature Health:** See exactly which AOB patterns broke after a game update.
* **Audit Log:** Watch a terminal feed of every command Cursor/Claude is executing on your debugger.

*(Insert GIF of Dashboard Here)*

---

## 🚀 Installation

Install universally via pip:

```bash
pip install nexusre-mcp[all]
```

### Quick Start
To attach NexusRE to Cursor or Claude Desktop automatically:
```bash
nexusre-mcp --install
```

To run the secure network-wide SSE server (with rate limiting and API key auth) so your dev team can connect remotely:
```bash
set NEXUSRE_API_KEY=your_secret_key
nexusre-mcp --transport sse --port 8080
```

---

## 🔌 Supported Backends

NexusRE is modular. Drop any `.py` file into the `adapters/` folder and it auto-registers.

| Environment | Type | Best For |
|---|---|---|
| **IDA Pro** | Static | Decompilation, Struct generation, X-refs |
| **Ghidra** | Static | Headless analysis, Symbol resolution |
| **x64dbg** | Dynamic | Live instruction patching, Register reading |
| **Cheat Engine** | Dynamic | Multi-level pointer chasing, Lua environments |
| **Frida** | Dynamic | JavaScript instruction trapping and hooking |
| **DMA / PCILeech**| Hardware | 100% undetected memory read/writes |

## 🛠 Usage in Cursor IDE
1. Open Cursor Settings -> Features -> MCP Servers
2. Add new server: `nexusre`
3. Command: `uv run main.py`
4. Open the AI pane and tell Cursor: *"Initialize an x64dbg session and scan for this player health AOB."*

<div align="center">
<i>Built for the modern reverse engineer.</i>
</div>
