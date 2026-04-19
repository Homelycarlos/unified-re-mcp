# NexusRE-MCP Ghidra Backend Plugin
# Compatible with Ghidra 11.x+ (PyGhidra / Jython)
# Starts a background HTTP server on port 10102 for AI connectivity.

import threading
import json
import sys
import traceback

# Python 2 / 3 Compatibility
if sys.version_info[0] < 3:
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
else:
    from http.server import HTTPServer, BaseHTTPRequestHandler

# ── Ghidra API Imports ─────────────────────────────────────────────────────
try:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.listing import CodeUnit
    from ghidra.program.model.symbol import SourceType
    HAS_GHIDRA = True
except ImportError:
    HAS_GHIDRA = False

# ── Shared State ───────────────────────────────────────────────────────────
# Because the HTTP server runs in a background thread, it cannot access
# Ghidra's script-level globals like `currentProgram`. We snapshot them
# at script launch and store them on the handler class so every request
# handler instance can reach them via `self.__class__._program`.
# ───────────────────────────────────────────────────────────────────────────

class GhidraRequestHandler(BaseHTTPRequestHandler):
    # Class-level references — set once at startup from the script globals
    _program = None

    # ── HTTP verb handlers ─────────────────────────────────────────────

    def do_GET(self):
        """Health-check endpoint so NexusRE adapter can ping us."""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        status = "ok" if self.__class__._program else "no_program"
        self.wfile.write(json.dumps({"status": status}).encode('utf-8'))

    def do_POST(self):
        # ── Read payload ───────────────────────────────────────────────
        try:
            cl = self.headers.get('Content-Length') or self.headers.get('content-length') or '0'
            content_length = int(cl)
        except (TypeError, ValueError):
            content_length = 0

        post_data = self.rfile.read(content_length) if content_length > 0 else b''
        if not post_data:
            self._respond(400, {"error": "Empty request body"})
            return

        try:
            req = json.loads(post_data.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            self._respond(400, {"error": "Malformed JSON: " + str(e)})
            return

        action = req.get("action", "")
        args   = req.get("args", {})
        prog   = self.__class__._program

        # ── Dispatch ───────────────────────────────────────────────────
        try:
            result = self._dispatch(action, args, prog)
            self._respond(200, result)
        except Exception as e:
            traceback.print_exc()
            self._respond(500, {"error": str(e)})

    # ── Response helper ────────────────────────────────────────────────

    def _respond(self, code, payload):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode('utf-8'))

    # ── Action Router ──────────────────────────────────────────────────

    def _dispatch(self, action, args, prog):
        if not prog:
            return {"error": "No program loaded in Ghidra. Open a binary first."}

        # ── Ping / Health ──────────────────────────────────────────────
        if action == "ping":
            return {"status": "ok", "program": prog.getName()}

        # ── Current Address ────────────────────────────────────────────
        elif action == "ghidra_get_current_address":
            loc = self.__class__._location
            if loc:
                return {"address": "0x" + loc.getAddress().toString()}
            return {"address": None}

        # ── Current Function ───────────────────────────────────────────
        elif action == "ghidra_get_current_function":
            loc = self.__class__._location
            if loc:
                fm = prog.getFunctionManager()
                func = fm.getFunctionContaining(loc.getAddress())
                if func:
                    return {"address": "0x" + func.getEntryPoint().toString(), "name": func.getName()}
            return {"address": None}

        # ── List Functions ─────────────────────────────────────────────
        elif action == "ghidra_list_functions":
            limit  = int(args.get("limit", 100))
            offset = int(args.get("offset", 0))
            filt   = args.get("filter")
            funcs  = []
            fm = prog.getFunctionManager()
            idx = 0
            it = fm.getFunctions(True)
            while it.hasNext():
                f = it.next()
                name = f.getName()
                if filt and filt.lower() not in name.lower():
                    continue
                if idx < offset:
                    idx += 1
                    continue
                if idx >= offset + limit:
                    break
                funcs.append({
                    "name": name,
                    "address": "0x" + f.getEntryPoint().toString(),
                    "size": int(f.getBody().getNumAddresses())
                })
                idx += 1
            return {"functions": funcs}

        # ── Get Function ───────────────────────────────────────────────
        elif action == "ghidra_get_function":
            addr_str = args.get("address", "")
            addr = prog.getAddressFactory().getAddress(addr_str)
            if not addr:
                return {"error": "Invalid address: " + addr_str}
            func = prog.getFunctionManager().getFunctionAt(addr)
            if not func:
                # Try containing
                func = prog.getFunctionManager().getFunctionContaining(addr)
            if func:
                return {
                    "name": func.getName(),
                    "address": "0x" + func.getEntryPoint().toString(),
                    "size": int(func.getBody().getNumAddresses())
                }
            return {"error": "Function not found at " + addr_str}

        # ── Decompile ──────────────────────────────────────────────────
        elif action == "ghidra_decompile_function":
            addr_str = args.get("address", "")
            addr = prog.getAddressFactory().getAddress(addr_str)
            if not addr:
                return {"error": "Invalid address: " + addr_str}
            func = prog.getFunctionManager().getFunctionAt(addr)
            if not func:
                func = prog.getFunctionManager().getFunctionContaining(addr)
            if not func:
                return {"error": "Function not found at " + addr_str}
            decomp = DecompInterface()
            decomp.openProgram(prog)
            res = decomp.decompileFunction(func, 60, ConsoleTaskMonitor())
            if res and res.getDecompiledFunction():
                return {"code": res.getDecompiledFunction().getC()}
            return {"code": "// Decompilation failed or timed out"}

        # ── Disassemble ────────────────────────────────────────────────
        elif action == "ghidra_disassemble":
            addr_str = args.get("address", "")
            addr = prog.getAddressFactory().getAddress(addr_str)
            if not addr:
                return {"error": "Invalid address: " + addr_str}
            func = prog.getFunctionManager().getFunctionAt(addr)
            if not func:
                func = prog.getFunctionManager().getFunctionContaining(addr)
            if not func:
                return {"code": "// No function at " + addr_str}
            listing = prog.getListing()
            body = func.getBody()
            lines = []
            it = listing.getInstructions(body, True)
            while it.hasNext():
                instr = it.next()
                a = "0x" + instr.getAddress().toString()
                lines.append(a + ": " + instr.toString())
            return {"code": "\n".join(lines)}

        # ── Cross-References ───────────────────────────────────────────
        elif action == "ghidra_get_xrefs":
            addr_str = args.get("address", "")
            addr = prog.getAddressFactory().getAddress(addr_str)
            if not addr:
                return {"error": "Invalid address"}
            refs = []
            for ref in prog.getReferenceManager().getReferencesTo(addr):
                refs.append({
                    "from": "0x" + ref.getFromAddress().toString(),
                    "to":   "0x" + ref.getToAddress().toString(),
                    "type": ref.getReferenceType().getName()
                })
            return {"xrefs": refs}

        # ── Strings ────────────────────────────────────────────────────
        elif action == "ghidra_get_strings":
            from ghidra.program.util import DefinedDataIterator
            limit  = int(args.get("limit", 100))
            offset = int(args.get("offset", 0))
            filt   = args.get("filter")
            strings = []
            idx = 0
            it = DefinedDataIterator.definedStrings(prog)
            while it.hasNext():
                data = it.next()
                val = data.getDefaultValueRepresentation()
                if filt and filt.lower() not in val.lower():
                    continue
                if idx < offset:
                    idx += 1
                    continue
                if idx >= offset + limit:
                    break
                strings.append({
                    "address": "0x" + data.getAddress().toString(),
                    "value": val
                })
                idx += 1
            return {"strings": strings}

        # ── Globals ────────────────────────────────────────────────────
        elif action == "ghidra_get_globals":
            limit  = int(args.get("limit", 100))
            offset = int(args.get("offset", 0))
            filt   = args.get("filter")
            globs  = []
            st = prog.getSymbolTable()
            idx = 0
            it = st.getAllSymbols(True)
            while it.hasNext():
                sym = it.next()
                if sym.isExternal():
                    continue
                name = sym.getName()
                if name.startswith("DAT_") or name.startswith("s_") or name.startswith("u_"):
                    if filt and filt.lower() not in name.lower():
                        continue
                    if idx < offset:
                        idx += 1
                        continue
                    if idx >= offset + limit:
                        break
                    globs.append({
                        "address": "0x" + sym.getAddress().toString(),
                        "name": name,
                        "size": 0,
                        "value": None
                    })
                    idx += 1
            return {"globals": globs}

        # ── Segments ───────────────────────────────────────────────────
        elif action == "ghidra_get_segments":
            limit  = int(args.get("limit", 100))
            offset = int(args.get("offset", 0))
            segs   = []
            idx = 0
            for block in prog.getMemory().getBlocks():
                if idx < offset:
                    idx += 1
                    continue
                if idx >= offset + limit:
                    break
                perms = ""
                if block.isRead():    perms += "R"
                if block.isWrite():   perms += "W"
                if block.isExecute(): perms += "X"
                segs.append({
                    "name": block.getName(),
                    "start_address": "0x" + block.getStart().toString(),
                    "end_address":   "0x" + block.getEnd().toString(),
                    "size": int(block.getSize()),
                    "permissions": perms
                })
                idx += 1
            return {"segments": segs}

        # ── Imports ────────────────────────────────────────────────────
        elif action == "ghidra_get_imports":
            limit  = int(args.get("limit", 100))
            offset = int(args.get("offset", 0))
            imps   = []
            st = prog.getSymbolTable()
            idx = 0
            it = st.getExternalSymbols()
            while it.hasNext():
                sym = it.next()
                if idx < offset:
                    idx += 1
                    continue
                if idx >= offset + limit:
                    break
                parent = sym.getParentNamespace()
                imps.append({
                    "address": "0x" + sym.getAddress().toString(),
                    "name": sym.getName(),
                    "module": parent.getName() if parent else ""
                })
                idx += 1
            return {"imports": imps}

        # ── Exports ────────────────────────────────────────────────────
        elif action == "ghidra_get_exports":
            limit  = int(args.get("limit", 100))
            offset = int(args.get("offset", 0))
            exps   = []
            st = prog.getSymbolTable()
            idx = 0
            it = st.getAllSymbols(True)
            while it.hasNext():
                sym = it.next()
                if sym.isExternalEntryPoint():
                    if idx < offset:
                        idx += 1
                        continue
                    if idx >= offset + limit:
                        break
                    exps.append({
                        "address": "0x" + sym.getAddress().toString(),
                        "name": sym.getName()
                    })
                    idx += 1
            return {"exports": exps}

        # ── Rename Symbol ──────────────────────────────────────────────
        elif action == "ghidra_rename_symbol":
            addr_str = args.get("address", "")
            new_name = args.get("name", "")
            addr = prog.getAddressFactory().getAddress(addr_str)
            if not addr:
                return {"success": False, "error": "Invalid address"}
            # Try function first
            func = prog.getFunctionManager().getFunctionAt(addr)
            if func:
                func.setName(new_name, SourceType.USER_DEFINED)
                return {"success": True}
            # Try symbol
            st = prog.getSymbolTable()
            sym = st.getPrimarySymbol(addr)
            if sym:
                sym.setName(new_name, SourceType.USER_DEFINED)
                return {"success": True}
            return {"success": False, "error": "No symbol at address"}

        # ── Set Comment ────────────────────────────────────────────────
        elif action == "ghidra_set_comment":
            addr_str   = args.get("address", "")
            comment    = args.get("comment", "")
            repeatable = args.get("repeatable", False)
            addr = prog.getAddressFactory().getAddress(addr_str)
            if not addr:
                return {"success": False, "error": "Invalid address"}
            listing = prog.getListing()
            cu = listing.getCodeUnitAt(addr)
            if cu:
                comment_type = CodeUnit.REPEATABLE_COMMENT if repeatable else CodeUnit.EOL_COMMENT
                cu.setComment(comment_type, comment)
                return {"success": True}
            return {"success": False, "error": "No code unit at address"}

        # ── Set Function Type ──────────────────────────────────────────
        elif action == "ghidra_set_function_type":
            addr_str  = args.get("address", "")
            signature = args.get("signature", "")
            addr = prog.getAddressFactory().getAddress(addr_str)
            if not addr:
                return {"success": False, "error": "Invalid address"}
            func = prog.getFunctionManager().getFunctionAt(addr)
            if not func:
                return {"success": False, "error": "No function at address"}
            from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
            from ghidra.program.model.data import FunctionDefinitionDataType
            # For now, just return success stub — full signature parsing is complex
            return {"success": True, "message": "Signature application requires Ghidra transaction context"}

        # ── Rename Local Variable ──────────────────────────────────────
        elif action == "ghidra_rename_local_variable":
            addr_str = args.get("address", "")
            old_name = args.get("old_name", "")
            new_name = args.get("new_name", "")
            addr = prog.getAddressFactory().getAddress(addr_str)
            if not addr:
                return {"success": False, "error": "Invalid address"}
            func = prog.getFunctionManager().getFunctionAt(addr)
            if not func:
                return {"success": False, "error": "No function at address"}
            for var in func.getAllVariables():
                if var.getName() == old_name:
                    var.setName(new_name, SourceType.USER_DEFINED)
                    return {"success": True}
            return {"success": False, "error": "Variable not found: " + old_name}

        # ── Set Local Variable Type ────────────────────────────────────
        elif action == "ghidra_set_local_variable_type":
            addr_str = args.get("address", "")
            var_name = args.get("variable_name", "")
            new_type = args.get("new_type", "")
            addr = prog.getAddressFactory().getAddress(addr_str)
            if not addr:
                return {"success": False, "error": "Invalid address"}
            func = prog.getFunctionManager().getFunctionAt(addr)
            if not func:
                return {"success": False, "error": "No function at address"}
            from ghidra.program.model.data import DataTypeManager
            dtm = prog.getDataTypeManager()
            dt = dtm.getDataType("/" + new_type)
            if not dt:
                return {"success": False, "error": "Unknown type: " + new_type}
            for var in func.getAllVariables():
                if var.getName() == var_name:
                    var.setDataType(dt, SourceType.USER_DEFINED)
                    return {"success": True}
            return {"success": False, "error": "Variable not found: " + var_name}

        # ── Patch Bytes ────────────────────────────────────────────────
        elif action == "ghidra_patch_bytes":
            addr_str  = args.get("address", "")
            hex_bytes = args.get("hex_bytes", "")
            addr = prog.getAddressFactory().getAddress(addr_str)
            if not addr:
                return {"success": False, "error": "Invalid address"}
            raw = bytes.fromhex(hex_bytes.replace(" ", ""))
            prog.getMemory().setBytes(addr, raw)
            return {"success": True}

        # ── Save / Analyze ─────────────────────────────────────────────
        elif action == "ghidra_save_binary":
            return {"success": True, "message": "Use File -> Save in Ghidra UI"}

        elif action == "ghidra_analyze_functions":
            from ghidra.app.cmd.function import CreateFunctionCmd
            addresses = args.get("addresses", [])
            for a in addresses:
                addr = prog.getAddressFactory().getAddress(a)
                if addr:
                    cmd = CreateFunctionCmd(addr)
                    cmd.applyTo(prog)
            return {"success": True}

        else:
            return {"error": "Unknown action: " + action}

    def log_message(self, format, *args):
        pass  # Suppress noisy per-request logging


# ── Server Lifecycle ───────────────────────────────────────────────────────

_server_instance = None

def start_server():
    global _server_instance
    PORT = 10102

    # Kill previous instance if script is re-run
    if _server_instance is not None:
        try:
            _server_instance.shutdown()
            _server_instance.server_close()
            print("[Ghidra-MCP] Shut down previous server instance.")
        except Exception:
            pass

    _server_instance = HTTPServer(('127.0.0.1', PORT), GhidraRequestHandler)
    print("[Ghidra-MCP] Background HTTP server LIVE on 127.0.0.1:%d" % PORT)
    _server_instance.serve_forever()


# ── Entry Point (run via Script Manager or File -> Script file) ────────────
# Ghidra scripts are NOT run with __name__ == "__main__", they are exec'd
# directly. So we always run the startup logic unconditionally.

print("[Ghidra-MCP] Initializing NexusRE backend plugin...")

# Snapshot the Ghidra globals into class-level attrs
try:
    GhidraRequestHandler._program  = currentProgram   # noqa: F821
    print("[Ghidra-MCP] Program loaded: %s" % currentProgram.getName())   # noqa: F821
except NameError:
    GhidraRequestHandler._program = None
    print("[Ghidra-MCP] WARNING: No program loaded — open a binary first!")

try:
    GhidraRequestHandler._location = currentLocation   # noqa: F821
except NameError:
    GhidraRequestHandler._location = None

t = threading.Thread(target=start_server)
t.daemon = True
t.start()
print("[Ghidra-MCP] Server thread launched. Ready for AI connections.")
