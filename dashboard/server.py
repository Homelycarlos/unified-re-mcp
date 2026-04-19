"""
NexusRE Dashboard Server

Lightweight HTTP server that serves the dashboard UI and provides
a JSON API for live status updates. Runs alongside the MCP server.
"""
import http.server
import json
import os
import threading
import logging

logger = logging.getLogger("NexusRE")

DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))


class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    """Custom handler that serves the dashboard and provides API endpoints."""

    def __init__(self, *args, session_manager=None, **kwargs):
        self._sm = session_manager
        super().__init__(*args, directory=DASHBOARD_DIR, **kwargs)

    def do_GET(self):
        if self.path == '/api/status':
            self.send_json_response(self._get_status())
        elif self.path == '/' or self.path == '/index.html':
            super().do_GET()
        else:
            super().do_GET()

    def _get_status(self) -> dict:
        """Aggregate status from all subsystems."""
        status = {}

        # Backends
        try:
            from core.auto_session import detect_running_backends
            detected = detect_running_backends()
            status["backends"] = {
                "detected": [{"backend": b["backend"], "status": "already_exists"} for b in detected]
            }
        except Exception:
            status["backends"] = {"detected": []}

        # Sessions
        try:
            if self._sm:
                status["sessions"] = self._sm.list_sessions()
            else:
                status["sessions"] = []
        except Exception:
            status["sessions"] = []

        # Cache
        try:
            from core.cache import decompile_cache, function_cache, disasm_cache
            status["cache"] = {
                "decompile": decompile_cache.stats(),
                "function": function_cache.stats(),
                "disasm": disasm_cache.stats()
            }
        except Exception:
            status["cache"] = {}

        # Diffs
        try:
            from core.diff_engine import diff_engine
            history = diff_engine.get_history(limit=20)
            status["diffs"] = history
        except Exception:
            status["diffs"] = []

        # Similarity index
        try:
            from core.similarity import similarity_engine
            status["indexed"] = similarity_engine.index_count()
        except Exception:
            status["indexed"] = 0

        return status

    def send_json_response(self, data: dict):
        """Send a JSON response with CORS headers."""
        body = json.dumps(data).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        """Suppress default access logs to keep console clean."""
        pass


def start_dashboard(port: int = 7777, session_manager=None):
    """Start the dashboard on a background thread."""
    def _handler(*args, **kwargs):
        return DashboardHandler(*args, session_manager=session_manager, **kwargs)

    server = http.server.HTTPServer(('127.0.0.1', port), _handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True, name="NexusRE-Dashboard")
    thread.start()
    logger.info(f"[Dashboard] Live at http://127.0.0.1:{port}")
    print(f"[+] Dashboard: http://127.0.0.1:{port}")
    return server
