<br/>
<div align="center">

# ⚡ NexusRE MCP
**The Universal AI Bridge for Game Hacking & Reverse Engineering**

[![PyPI version](https://badge.fury.io/py/nexusre-mcp.svg)](https://badge.fury.io/py/nexusre-mcp)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Discord](https://img.shields.io/discord/1234567890?label=Discord&logo=discord&color=5865F2)](https://discord.gg/nexusre)

[Features](#-killer-features) • [Installation](#-installation) • [Supported Backends](#-supported-backends)

</div>

**NexusRE** is an Enterprise-grade Model Context Protocol (MCP) server that connects your AI assistants (Cursor, Claude, Windsurf) directly to your reverse engineering environments. 

Instead of writing isolated scripts for IDA, x64dbg, or Cheat Engine, NexusRE acts as a universal adapter. You can highlight a piece of C++ SDK code in Cursor and say, *"Check my live x64dbg session to see what the register value is here,"* and the AI will do exactly that.

---

## 🔥 Killer Features

### 1. The "Game Updated" Auto-Healer (The Biggest Selling Point)
Every time a game updates, cheats break because memory offsets and AOBs (signatures) change. Usually, a developer has to drop everything, open IDA, and spend hours fixing them.

**The Pitch**: Tell them NexusRE has an AI-driven `auto_recover_signatures` engine. When a game patches, the MCP automatically diffs the old signatures, analyzes the cross-references in the new binary, and spits out a fixed `offsets.json`. What used to take 4 hours now takes 4 minutes.

### 2. The Universal Bridge
Usually, a developer writes a Python script for IDA, a Lua script for Cheat Engine, and a C++ plugin for x64dbg.

**The Pitch**: NexusRE lets you connect Cursor or Claude to all of them at once. You can highlight a piece of C++ SDK code in Cursor and say, *"Claude, check x64dbg to see what the live register value is here,"* and the AI will actually reach into the debugger and check for you.

<div align="center">
  <i>/i>
</div>

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
| **Frida** | Dynamic | JavaScript instruction trapping, Live Breakpoints |
| **Kernel** | Ring-0 | Bypass user-mode AntiCheats via IOCTL (BYOD - Bring Your Own Driver)* |
| **DMA / PCILeech**| Hardware | 100% undetected memory read/writes |

_*Note: The `kernel` adapter is an empty template. You must add your own custom Kernel Driver (with its specific IOCTL byte layout) to utilize it!_

### Recent Feature Upgrades
* **DMA / PCILeech Hardware Integration**: Added `adapters/dma.py` utilizing the `vmmpy` library! The AI can now perform 100% undetected physical memory reads directly across a PCIe FPGA board, bypassing Vanguard and BattlEye entirely via a 2nd PC.
* **Automated C++ SDK Generator**: Call `generate_game_sdk` and the AI will recursively rip through an entire Engine (Unreal/Unity), parse the VTables and GObjects, and write a massive, complete C++ header struct mapping file for your cheat instantly.
* **Symbolic Decryption Solver**: Added `symbolic_string_decrypt` leveraging the `angr` engine. If a game uses a complex `ROL/XOR` chain to encrypt a pointer, you give the AI the memory block, and it will symbolically derive the algebraic decryption key and formula for you without manual debugging.
* **Kernel Scaffold Generator**: Start a new cheat project instantly by calling `scaffold_kernel_interface`. The AI will generate a complete boilerplate `driver.c` and `client.h` mapped to your specific game and desired IOCTL codes.
* **ReClass.NET Integration**: A native `ReClassAdapter` (`adapters/reclass.py`) allows AI to read active `.rcnet` project files to parse offset schemas and automatically generate C++ structs for your `driver.h`.
* **Kernel Fast-Pointer Scanning**: The new `CheatEngineAdapter` (`adapters/cheatengine.py`) hooks directly into CE's DBK64 lua backend. This gives the AI the power to execute milliseconds-fast native kernel pointer scans over massive Memory Regions.
* **Automated Signature Generator**: `generate_unique_aob` added. Pass any memory address, and the server natively reads the assembly, wildcards volatile bytes, and verifies uniqueness—generating a perfect signature instantly.
* **RTTI & VTable Dumper**: The `dump_vtables` tool added to automatically rip C++ Run-Time Type Information to accurately map Virtual Method Table functions and offsets without manual disassembly.
* **The "Auto-Healer"**: The `auto_recover_signatures` endpoint is now fully functional! It uses an algorithmic wildcard fuzzy scanner to automatically restore slightly broken memory signatures during game updates without needing human intervention.
* **Network & Packet Interception**: A brand new `NetworkAdapter` (via `adapters/network.py`) hooked into the MCP allows your AI to perform pure L3/L4 Winsock filtering to capture Game Packets securely from outside the game.
* **Headless Pointer Scanner**: The `generate_pointer_map` tool allows the AI to automatically walk memory regions backward to trace dynamic heap structures back to their static `.exe` bases natively.
* **Bulk Memory Dumper**: `dump_memory_region_to_file` added, enabling the AI to pull massive heaps of game memory directly onto the local drive for insanely fast local heuristics.
* **Dynamic Breakpoints**: Through the Frida adapter, AI can now programmatically set `set_hardware_breakpoint` and `wait_for_breakpoint` to halt game execution and dump live CPU registers instantly.
* **Stealth Kernel YARA Scanning**: The `yara_memory_scan` tool now natively supports the Kernel adapter. Once you bind your own driver to the `KernelAdapter`, `yara_memory_scan` will route all physical memory reads through Ring-0, entirely avoiding `VirtualQueryEx` bans from BattlEye/EAC.
* **Unity IL2CPP Dumper**: Added `dump_il2cpp_domain` alongside the native Unreal Engine structure dumpers.

## 🛠 Client & Debugger Installation Guide

### 1. Connecting to your AI (Claude / Cursor)
* **Cursor**: 
   - Navigate to `Settings -> Features -> MCP Servers`
   - Add new server named `NexusRE`
   - Set the command to: `uv run main.py` (or whatever executes your local python entrypoint).
* **Claude Desktop**:
   - Open your `claude_desktop_config.json`
   - Add the NexusRE server node mapping to your local repository.
* Once linked, simply tell your AI: *"Initialize an IDA session and use `wait_for_breakpoint` on this offset."*

### 2. Connecting the IDA Pro Plugin
For NexusRE to natively control IDA Pro (and its debugger), you must install the backend plugin into IDA:
1. Locate the plugin file inside this repository at: `plugins/ida/ida_backend_plugin.py`
2. Copy the file and paste it into your IDA Pro plugins directory:
   - Typical path: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
   - Fallback path: `C:\Program Files\IDA Professional\plugins\`
3. Restart IDA Pro. The plugin is configured with `idaapi.PLUGIN_FIX`, meaning it will automatically start the background connection listener every time you open a database!

<div align="center">
<i>Built for the modern reverse engineer.</i>
</div>
