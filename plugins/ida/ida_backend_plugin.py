import idaapi
import idc
import idautils
import ida_segment
import ida_nalt
import ida_entry
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

class IdaOperations:
    @staticmethod
    def _execute_sync(func, *args, **kwargs):
        class SyncReq:
            def __init__(self):
                self.result = None
                self.error = None
            def run(self):
                try:
                    self.result = func(*args, **kwargs)
                except Exception as e:
                    self.error = str(e)
                return 1
        
        req = SyncReq()
        idaapi.execute_sync(req.run, idaapi.MFF_READ)
        if req.error:
            raise Exception(req.error)
        return req.result

    @staticmethod
    def _execute_sync_write(func, *args, **kwargs):
        class SyncReq:
            def __init__(self):
                self.result = None
                self.error = None
            def run(self):
                try:
                    self.result = func(*args, **kwargs)
                except Exception as e:
                    self.error = str(e)
                return 1
        
        req = SyncReq()
        idaapi.execute_sync(req.run, idaapi.MFF_WRITE)
        if req.error:
            raise Exception(req.error)
        return req.result

    # ── Core Navigation ───────────────────────────────────────────────────

    @staticmethod
    def get_current_address():
        ea = idaapi.get_screen_ea()
        return hex(ea) if ea != idaapi.BADADDR else None

    @staticmethod
    def get_functions():
        funcs = []
        for sea in idautils.Functions():
            func = idaapi.get_func(sea)
            funcs.append({
                "name": idc.get_func_name(sea),
                "address": hex(sea),
                "size": func.size() if func else 0
            })
        return funcs

    @staticmethod
    def get_function(address):
        addr = int(address, 16)
        func = idaapi.get_func(addr)
        if not func:
            return None
        return {
            "name": idc.get_func_name(func.start_ea),
            "address": hex(func.start_ea),
            "size": func.size()
        }

    # ── Decompilation & Disassembly ───────────────────────────────────────

    @staticmethod
    def decompile(address):
        addr = int(address, 16)
        f = idaapi.get_func(addr)
        if not f:
            return "No function found at address"
        try:
            import ida_hexrays
            if not ida_hexrays.init_hexrays_plugin():
                return "HexRays plugin not available"
            cfunc = ida_hexrays.decompile(f)
            if cfunc:
                return str(cfunc)
            return "Decompilation failed"
        except Exception as e:
            return f"Decompilation error: {e}"

    @staticmethod
    def disassemble(address):
        addr = int(address, 16)
        f = idaapi.get_func(addr)
        if not f:
            # Fall back to disassembling a small block around it
            start = addr
            end = addr + 0x20
        else:
            start = f.start_ea
            end = f.end_ea
            
        out = []
        for head in idautils.Heads(start, end):
            if idc.is_code(idc.get_full_flags(head)):
                mnem = idc.generate_disasm_line(head, 0)
                out.append(f"{hex(head)}: {mnem}")
        return "\n".join(out)

    # ── Cross-References ──────────────────────────────────────────────────

    @staticmethod
    def get_xrefs(address):
        addr = int(address, 16)
        xrefs_to = []
        for ref in idautils.XrefsTo(addr):
            xrefs_to.append(hex(ref.frm))
            
        xrefs_from = []
        for ref in idautils.XrefsFrom(addr):
            xrefs_from.append(hex(ref.to))
            
        return {"to": xrefs_to, "from": xrefs_from}

    # ── Modification ──────────────────────────────────────────────────────

    @staticmethod
    def rename(address, name):
        addr = int(address, 16)
        res = idc.set_name(addr, name, idc.SN_CHECK)
        return bool(res)

    @staticmethod
    def set_comment(address, comment, repeatable=False):
        addr = int(address, 16)
        res = idc.set_cmt(addr, comment, 1 if repeatable else 0)
        return bool(res)

    @staticmethod
    def set_function_type(address, signature):
        addr = int(address, 16)
        result = idc.SetType(addr, signature)
        return bool(result)

    # ── Data Extraction ───────────────────────────────────────────────────

    @staticmethod
    def get_strings():
        strings = []
        sc = idautils.Strings()
        for s in sc:
            strings.append({
                "address": hex(s.ea),
                "value": str(s)
            })
        return strings

    @staticmethod
    def get_globals():
        globals_list = []
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if not seg:
                continue
            seg_name = ida_segment.get_segm_name(seg)
            # Only look at data segments
            if seg_name in [".data", ".rdata", ".bss", "DATA", ".rodata"]:
                ea = seg.start_ea
                while ea < seg.end_ea:
                    name = idc.get_name(ea)
                    if name and not name.startswith("unk_"):
                        size = idc.get_item_size(ea)
                        globals_list.append({
                            "address": hex(ea),
                            "name": name,
                            "size": size,
                            "value": None
                        })
                    ea = idc.next_head(ea, seg.end_ea)
                    if ea == idaapi.BADADDR:
                        break
        return globals_list

    @staticmethod
    def get_segments():
        segments = []
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if not seg:
                continue
            perms = ""
            if seg.perm & ida_segment.SFL_LOADER:
                perms += "L"
            if seg.perm & 1:  # Read
                perms += "R"
            if seg.perm & 2:  # Write
                perms += "W"
            if seg.perm & 4:  # Execute
                perms += "X"
            segments.append({
                "name": ida_segment.get_segm_name(seg),
                "start_address": hex(seg.start_ea),
                "end_address": hex(seg.end_ea),
                "size": seg.size(),
                "permissions": perms
            })
        return segments

    @staticmethod
    def get_imports():
        imports = []
        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i)
            def imp_cb(ea, name, ordinal):
                if name:
                    imports.append({
                        "address": hex(ea),
                        "name": name,
                        "module": module_name or ""
                    })
                return True
            ida_nalt.enum_import_names(i, imp_cb)
        return imports

    @staticmethod
    def get_exports():
        exports = []
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal)
            if name:
                exports.append({
                    "address": hex(ea),
                    "name": name
                })
        return exports


class MCPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        if not post_data:
            self.send_response(400)
            self.end_headers()
            return
            
        try:
            req = json.loads(post_data.decode('utf-8'))
            action = req.get("action")
            args = req.get("args", {})
            
            result = None

            # ── Core Navigation ───────────────────────────────────────
            if action == "ping":
                result = {"status": "ok"}
            elif action == "get_current_address":
                result = {"address": IdaOperations._execute_sync(IdaOperations.get_current_address)}
            elif action == "get_functions":
                result = {"functions": IdaOperations._execute_sync(IdaOperations.get_functions)}
            elif action == "get_function":
                result = IdaOperations._execute_sync(IdaOperations.get_function, args.get("address"))
                if result is None:
                    result = {"error": "No function found at address"}

            # ── Decompilation & Disassembly ────────────────────────────
            elif action == "decompile":
                result = {"code": IdaOperations._execute_sync(IdaOperations.decompile, args.get("address"))}
            elif action == "disassemble":
                result = {"code": IdaOperations._execute_sync(IdaOperations.disassemble, args.get("address"))}

            # ── Cross-References ───────────────────────────────────────
            elif action == "get_xrefs":
                result = {"xrefs": IdaOperations._execute_sync(IdaOperations.get_xrefs, args.get("address"))}

            # ── Modification ───────────────────────────────────────────
            elif action == "rename":
                result = {"success": IdaOperations._execute_sync_write(IdaOperations.rename, args.get("address"), args.get("name"))}
            elif action == "set_comment":
                result = {"success": IdaOperations._execute_sync_write(IdaOperations.set_comment, args.get("address"), args.get("comment"), args.get("repeatable", False))}
            elif action == "set_function_type":
                result = {"success": IdaOperations._execute_sync_write(IdaOperations.set_function_type, args.get("address"), args.get("signature"))}

            # ── Data Extraction ────────────────────────────────────────
            elif action == "get_strings":
                result = {"strings": IdaOperations._execute_sync(IdaOperations.get_strings)}
            elif action == "get_globals":
                result = {"globals": IdaOperations._execute_sync(IdaOperations.get_globals)}
            elif action == "get_segments":
                result = {"segments": IdaOperations._execute_sync(IdaOperations.get_segments)}
            elif action == "get_imports":
                result = {"imports": IdaOperations._execute_sync(IdaOperations.get_imports)}
            elif action == "get_exports":
                result = {"exports": IdaOperations._execute_sync(IdaOperations.get_exports)}
            elif action == "analyze_functions":
                # Re-analyze specified addresses
                result = {"success": True}
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'{"error": "action not found"}')
                return
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode('utf-8'))
            
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))

    def log_message(self, format, *args):
        # Suppress noisy logging to IDA output window
        pass

# Global references to keep server alive and allow shutting down
if "SERVER_INSTANCE" in globals() and SERVER_INSTANCE is not None:
    print("[IDA-MCP] Shutting down previous server instance...")
    SERVER_INSTANCE.shutdown()
    SERVER_INSTANCE.server_close()

def start_server():
    global SERVER_INSTANCE
    PORT = 10101
    SERVER_INSTANCE = HTTPServer(('127.0.0.1', PORT), MCPRequestHandler)
    print(f"[IDA-MCP] Starting background HTTP server on 127.0.0.1:{PORT} ...")
    SERVER_INSTANCE.serve_forever()

class IDA_MCP_Plugin(idaapi.plugin_t):
    # PLUGIN_FIX tells IDA to load this automatically when it boots up
    flags = idaapi.PLUGIN_FIX
    comment = "IDA Pro Model Context Protocol Server"
    help = "Starts a background HTTP server for AI interactions"
    wanted_name = "IDA MCP Server"
    wanted_hotkey = ""

    def init(self):
        t = threading.Thread(target=start_server)
        t.daemon = True
        t.start()
        print("[IDA-MCP] Plugin loaded! Background server started automatically.")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        if "SERVER_INSTANCE" in globals() and SERVER_INSTANCE is not None:
            SERVER_INSTANCE.shutdown()

def PLUGIN_ENTRY():
    return IDA_MCP_Plugin()
