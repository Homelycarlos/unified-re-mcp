import idaapi
import idc
import idautils
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

    @staticmethod
    def get_current_address():
        ea = idaapi.get_screen_ea()
        return hex(ea) if ea != idaapi.BADADDR else None

    @staticmethod
    def get_functions():
        funcs = []
        for sea in idautils.Functions():
            funcs.append({
                "name": idc.get_func_name(sea),
                "address": hex(sea)
            })
        return funcs

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
    def get_xrefs(address):
        addr = int(address, 16)
        xrefs_to = []
        for ref in idautils.XrefsTo(addr):
            xrefs_to.append(hex(ref.frm))
            
        xrefs_from = []
        for ref in idautils.XrefsFrom(addr):
            xrefs_from.append(hex(ref.to))
            
        return {"to": xrefs_to, "from": xrefs_from}

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
            if action == "ping":
                result = {"status": "ok"}
            elif action == "get_current_address":
                result = {"address": IdaOperations._execute_sync(IdaOperations.get_current_address)}
            elif action == "get_functions":
                result = {"functions": IdaOperations._execute_sync(IdaOperations.get_functions)}
            elif action == "decompile":
                result = {"code": IdaOperations._execute_sync(IdaOperations.decompile, args.get("address"))}
            elif action == "disassemble":
                result = {"code": IdaOperations._execute_sync(IdaOperations.disassemble, args.get("address"))}
            elif action == "rename":
                result = {"success": IdaOperations._execute_sync_write(IdaOperations.rename, args.get("address"), args.get("name"))}
            elif action == "set_comment":
                result = {"success": IdaOperations._execute_sync_write(IdaOperations.set_comment, args.get("address"), args.get("comment"), args.get("repeatable", False))}
            elif action == "get_xrefs":
                result = {"xrefs": IdaOperations._execute_sync(IdaOperations.get_xrefs, args.get("address"))}
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
