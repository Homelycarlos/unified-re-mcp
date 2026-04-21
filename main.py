import os
import sys
import json
import platform

# Ensure the root directory is accessible so modules resolve correctly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.server import mcp


def get_config_json() -> dict:
    """Generate the MCP client configuration JSON dynamically."""
    script_path = os.path.abspath(__file__)
    root_dir = os.path.dirname(script_path)
    venv_python = os.path.join(root_dir, ".venv", "Scripts", "python.exe") if platform.system() == "Windows" else os.path.join(root_dir, ".venv", "bin", "python")
    
    # If the user has already run 'uv sync', use the venv for zero-latency startup
    if os.path.exists(venv_python):
        return {
            "mcpServers": {
                "nexusre-mcp": {
                    "command": venv_python,
                    "args": [script_path]
                }
            }
        }
    
    # Fallback to uv run --with if no venv is found
    return {
        "mcpServers": {
            "nexusre-mcp": {
                "command": "uv",
                "args": [
                    "run",
                    "--with", "mcp[cli]",
                    "--with", "pydantic",
                    "--with", "aiohttp",
                    "--with", "frida",
                    "--with", "r2pipe",
                    "--with", "pymem",
                    "--with", "aiosqlite",
                    script_path
                ]
            }
        }
    }


def print_config():
    """Print the JSON configuration for manual copy-paste."""
    config = get_config_json()
    print("=========================================")
    print(" NEXUSRE-MCP SERVER CONFIGURATION")
    print("=========================================\n")
    print("Copy the JSON block below and paste it into your MCP client's configuration file:")
    print(" - Claude Desktop: %APPDATA%\\Claude\\claude_desktop_config.json or ~/Library/Application Support/Claude/claude_desktop_config.json")
    print(" - Cursor: Adds to your MCP settings or workspace mcp.json")
    print(" - VS Code (Cline / Roo): Autoconfigured to globalStorage")
    print(" - Zed: Autoconfigured to context_servers in settings.json")
    print(" - Windsurf: ~/.codeium/windsurf/mcp_config.json")
    print(" - Trae: Add to your project root .trae/mcp.json")
    print(" - Kiro IDE: ~/.kiro/settings/mcp.json\n")
    print(json.dumps(config, indent=2))
    print("\n=========================================")
    sys.exit(0)


def get_mcp_clients() -> dict:
    """Return a dictionary of supported MCP clients and their configurations."""
    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA", "")
    local_appdata = os.environ.get("LOCALAPPDATA", "")
    linux_conf = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    mac_app = os.path.join(home, "Library", "Application Support")

    def get_paths(win=None, mac=None, lin=None, extra=None):
        paths = []
        sys_os = platform.system()
        if sys_os == "Windows" and win: paths.append(win)
        elif sys_os == "Darwin" and mac: paths.append(mac)
        elif sys_os == "Linux" and lin: paths.append(lin)
        if extra: paths.extend(extra)
        return paths

    # Windows Store Claude
    uwp_claude = []
    if local_appdata:
        packages_dir = os.path.join(local_appdata, "Packages")
        if os.path.isdir(packages_dir):
            for entry in os.listdir(packages_dir):
                if entry.startswith("Claude_"):
                    uwp_claude.append(os.path.join(packages_dir, entry, "LocalCache", "Roaming", "Claude", "claude_desktop_config.json"))

    clients = {
        "Claude Desktop": {
            "type": "global",
            "key": "mcpServers",
            "paths": get_paths(
                win=os.path.join(appdata, "Claude", "claude_desktop_config.json") if appdata else None,
                mac=os.path.join(mac_app, "Claude", "claude_desktop_config.json"),
                lin=os.path.join(linux_conf, "Claude", "claude_desktop_config.json"),
                extra=uwp_claude
            )
        },
        "Cursor": {
            "type": "global",
            "key": "mcpServers",
            "paths": get_paths(
                win=os.path.join(appdata, "Cursor", "User", "globalStorage", "mcp.json") if appdata else None,
                mac=os.path.join(mac_app, "Cursor", "User", "globalStorage", "mcp.json"),
                lin=os.path.join(linux_conf, "Cursor", "User", "globalStorage", "mcp.json")
            )
        },
        "Windsurf IDE": {
            "type": "global",
            "key": "mcpServers",
            "paths": [os.path.join(home, ".codeium", "windsurf", "mcp_config.json")]
        },
        "Kiro IDE": {
            "type": "global",
            "key": "mcpServers",
            "paths": [os.path.join(home, ".kiro", "settings", "mcp.json")]
        },
        "Trae IDE": {
            "type": "global",
            "key": "mcpServers",
            "paths": [os.path.join(home, ".trae", "mcp.json")]
        },
        "Zed IDE": {
            "type": "global",
            "key": "context_servers",
            "paths": get_paths(
                win=os.path.join(local_appdata, "Zed", "settings.json") if local_appdata else None,
                mac=os.path.join(mac_app, "Zed", "settings.json"),
                lin=os.path.join(linux_conf, "zed", "settings.json")
            )
        },
        "Roo Code (VS Code)": {
            "type": "global",
            "key": "mcpServers",
            "paths": get_paths(
                win=os.path.join(appdata, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "cline_mcp_settings.json") if appdata else None,
                mac=os.path.join(mac_app, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "cline_mcp_settings.json"),
                lin=os.path.join(linux_conf, "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "cline_mcp_settings.json")
            )
        },
        "Cline (VS Code)": {
            "type": "global",
            "key": "mcpServers",
            "paths": get_paths(
                win=os.path.join(appdata, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json") if appdata else None,
                mac=os.path.join(mac_app, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
                lin=os.path.join(linux_conf, "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")
            )
        },
        "Claude Code (CLI)": {
            "type": "global",
            "key": "mcpServers",
            "paths": [os.path.join(home, ".claude.json")]
        },
        "LM Studio": {
            "type": "global",
            "key": "mcpServers",
            "paths": [os.path.join(home, ".cache", "lm-studio", "mcpServers.json")]
        },
        "VS Code Workspace": {
            "type": "workspace",
            "instructions": "Create a '.vscode/mcp.json' file locally."
        },
        "Copilot CLI": {
            "type": "unsupported",
            "instructions": "Does not natively support user-provided local MCP JSON files."
        },
        "Amazon Q Developer CLI": {
            "type": "unsupported",
            "instructions": "Proprietary CLI. Does not natively support global MCP JSON injection."
        },
        "Gemini CLI": {
            "type": "unsupported",
            "instructions": "Does not feature a global MCP config standard."
        },
        "Warp": {
            "type": "unsupported",
            "instructions": "Relies on Warp's internal workflow configuration settings."
        },
        "Crush IDE / Kilo Code / Opencode / Qodo Gen / Qwen Coder / Codex / Augment Code": {
            "type": "fallback",
            "instructions": "If these are VS Code forks/extensions, configure via '.vscode/mcp.json' or their extension settings."
        }
    }
    return clients

def auto_install():
    print("\n============================================")
    print("|     MCP UNIVERSAL AUTO-INSTALLER         |")
    print("============================================\n")
    config_fragment = get_config_json()
    server_key = "nexusre-mcp"
    server_block = config_fragment["mcpServers"][server_key]

    clients = get_mcp_clients()
    installed_count = 0
    unsupported = []

    for name, data in clients.items():
        if data["type"] != "global":
            unsupported.append((name, data))
            continue
            
        for path in data["paths"]:
            if not path:
                continue
            
            existing = {}
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        existing = json.load(f)
                except (json.JSONDecodeError, IOError):
                    existing = {}

            root_key = data["key"]
            if root_key not in existing:
                existing[root_key] = {}

            # Check if already installed
            if server_key in existing[root_key]:
                print(f"[OK] {name}")
                print(f"    Already configured -> {path}")
            else:
                print(f"[+] {name}")
                print(f"    Installing MCP config -> {path}")

            existing[root_key][server_key] = server_block
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(existing, f, indent=2)

            installed_count += 1
            print(f"    Done! Restart {name} for changes to take effect.\n")

    if installed_count == 0:
        print("[!] No standard MCP configuration files were written.")
    else:
        print(f"\n[*] Successfully configured {installed_count} client(s).\n")

    print("\n--- Manual Configuration Guide ---")
    for name, data in unsupported:
        print(f"- {name}: {data['instructions']}")

    print("\n============================================")
    sys.exit(0)

def auto_install_silent():
    config_fragment = get_config_json()
    server_key = "nexusre-mcp"
    server_block = config_fragment["mcpServers"][server_key]
    
    clients = get_mcp_clients()
    installed = 0

    for name, data in clients.items():
        if data["type"] != "global":
            continue
            
        for path in data["paths"]:
            if not path:
                continue
            
            existing = {}
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        existing = json.load(f)
                except:
                    pass

            root_key = data["key"]
            if root_key not in existing:
                existing[root_key] = {}
            
            if server_key not in existing[root_key]:
                existing[root_key][server_key] = server_block
                try:
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump(existing, f, indent=2)
                    print(f"  [+] {name} config updated")
                    installed += 1
                except:
                    pass

    if installed == 0:
        print("  [-] No standard MCP clients updated automatically.")

def quickstart():
    print("""
======================================================
|          NEXUSRE-MCP QUICKSTART GUIDE              |
======================================================

  Your first 5 minutes with NexusRE-MCP:

  -- STEP 1: CONNECT ---------------------------------
  | Open your target binary in IDA Pro or Ghidra.     |
  | The backend plugin starts automatically on the    |
  | default port (IDA:10101, Ghidra:10102).           |
  ----------------------------------------------------

  -- STEP 2: DETECT ----------------------------------
  | Ask the AI:                                       |
  |   "Detect my backends"                            |
  |                                                   |
  | NexusRE auto-probes all ports and creates         |
  | sessions. Zero configuration needed.              |
  ----------------------------------------------------

  -- STEP 3: ANALYZE ---------------------------------
  | Ask the AI:                                       |
  |   "Run full_analysis on the loaded binary"        |
  |                                                   |
  | This decompiles 200 functions, auto-annotates     |
  | crypto/networking/anti-cheat patterns, and runs   |
  | a vulnerability scan. One command.                |
  ----------------------------------------------------

  -- STEP 4: HUNT ------------------------------------
  | "Find functions similar to this decryption"       |
  | "Suggest names for the function at 0x140001234"   |
  | "Generate a YARA rule for this function"          |
  | "Show me the vulnerability report"                |
  ----------------------------------------------------

  -- STEP 5: EXPORT ----------------------------------
  | "Export all symbols as an IDA script"             |
  | "Sync symbols from IDA to Ghidra"                 |
  | "Generate a Frida hook for this function"         |
  ----------------------------------------------------


  💡 Pro tip: Every rename you do teaches the AI.
     The more you use it, the smarter it gets.
""")
    sys.exit(0)




def print_help():
    print("""
NexusRE-MCP Server v4.0
=======================================

Usage:
  nexusre-mcp                       Start the MCP server (stdio transport)
  nexusre-mcp setup                 One-command setup wizard
  nexusre-mcp quickstart            Interactive quickstart guide
  nexusre-mcp --config              Print JSON config for manual setup
  nexusre-mcp --install             Auto-inject config into Claude/Cursor
  nexusre-mcp --install-plugins     Auto-copy plugins to IDA/Ghidra/x64dbg
  nexusre-mcp --transport sse       Start with SSE transport (HTTP)
  nexusre-mcp --port 8080           Set the SSE server port
  nexusre-mcp --help                Show this help message

Supported Backends:
  - ida          (Port 10101)    - ghidra       (Port 10102)
  - x64dbg       (Port 10103)    - binja        (Port 10104)
  - cheatengine  (Port 10105)    - radare2      (Headless)
  - frida        (Headless)      - kernel       (Headless)
""")
    sys.exit(0)


def main_cli():
    if "--help" in sys.argv or "-h" in sys.argv:
        print_help()

    if "setup" in sys.argv:
        setup_wizard()

    if "quickstart" in sys.argv:
        quickstart()

    if "--config" in sys.argv:
        print_config()

    if "--install" in sys.argv:
        auto_install()

    if "--install-plugins" in sys.argv:
        install_plugins()

    # Determine transport mode
    import time
    transport = "stdio"
    port = 8080

    if "--transport" in sys.argv:
        idx = sys.argv.index("--transport")
        if idx + 1 < len(sys.argv):
            transport = sys.argv[idx + 1].lower()

    if "--port" in sys.argv:
        idx = sys.argv.index("--port")
        if idx + 1 < len(sys.argv):
            port = int(sys.argv[idx + 1])

    if transport == "sse":
        print(f"[*] Starting NEXUSRE-MCP SERVER with SSE transport on port {port}...")
        
        # Setup Auth & Rate Limiting for SSE
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.responses import JSONResponse
        from collections import defaultdict
        
        API_KEY = os.environ.get("NEXUSRE_API_KEY")
        if API_KEY:
            print("[+] API Key authentication ENABLED.")
        else:
            print("[!] Warning: NEXUSRE_API_KEY not set. API is unauthenticated!")

        class SecurityMiddleware(BaseHTTPMiddleware):
            def __init__(self, app):
                super().__init__(app)
                self.rate_limits = defaultdict(list)
                self.MAX_REQUESTS = 100  # 100 requests per minute

            async def dispatch(self, request, call_next):
                client_ip = request.client.host if request.client else "unknown"
                
                # Check Auth
                if API_KEY:
                    auth_header = request.headers.get("Authorization", "")
                    if auth_header != f"Bearer {API_KEY}":
                        return JSONResponse({"error": "Unauthorized. Invalid API Key."}, status_code=401)
                
                # Rate Limiting
                now = time.time()
                self.rate_limits[client_ip] = [t for t in self.rate_limits[client_ip] if now - t < 60]
                if len(self.rate_limits[client_ip]) >= self.MAX_REQUESTS:
                    return JSONResponse({"error": "Rate limit exceeded. Try again later."}, status_code=429)
                self.rate_limits[client_ip].append(now)

                return await call_next(request)

        # Inject middleware into FastMCP's underlying Starlette app
        mcp._app.add_middleware(SecurityMiddleware)

        mcp.run(transport="sse", port=port)
    else:
        # Start the fastMCP server via standard CLI execution (stdio)
        mcp.run()

if __name__ == "__main__":
    main_cli()

