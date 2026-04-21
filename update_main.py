import os
import re

main_path = "C:/Users/cmb16/.gemini/antigravity/scratch/unified-re-mcp/main.py"

with open(main_path, "r", encoding="utf-8") as f:
    text = f.read()

# We need to replace everything from _find_claude_config_paths to the end of auto_install_silent

match = re.search(r'def _find_claude_config_paths.*def quickstart\(\):', text, re.DOTALL)
if not match:
    print("Failed to find replacement block.")
    exit(1)

new_code = """def get_mcp_clients() -> dict:
    \"\"\"Return a dictionary of supported MCP clients and their configurations.\"\"\"
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
    print("\\n============================================")
    print("|     MCP UNIVERSAL AUTO-INSTALLER         |")
    print("============================================\\n")
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
            print(f"    Done! Restart {name} for changes to take effect.\\n")

    if installed_count == 0:
        print("[!] No standard MCP configuration files were written.")
    else:
        print(f"\\n[*] Successfully configured {installed_count} client(s).\\n")

    print("\\n--- Manual Configuration Guide ---")
    for name, data in unsupported:
        print(f"- {name}: {data['instructions']}")

    print("\\n============================================")
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

def quickstart():"""

text = text[:match.start()] + new_code + text[match.end()-len("def quickstart():"):]

with open(main_path, "w", encoding="utf-8") as f:
    f.write(text)

print("Successfully updated main.py with Universal MCP Auto-installer.")
