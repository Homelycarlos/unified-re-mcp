import json
import logging
from typing import List, Optional, Any
from mcp.server.fastmcp import FastMCP
from .session import SessionManager
from adapters.ida import IDAAdapter
from adapters.ghidra import GhidraAdapter
from schemas.models import FunctionSchema, StringSchema, XrefSchema, ErrorSchema

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("UnifiedMCP")

mcp = FastMCP("Unified Reverse Engineering MCP Server")
session_manager = SessionManager()

def get_adapter(session_id: str):
    session = session_manager.get_session(session_id)
    if not session:
        raise ValueError(f"Invalid session ID: {session_id}")
    if session.backend == "ida":
        return IDAAdapter(session.backend_url)
    elif session.backend == "ghidra":
        return GhidraAdapter(session.backend_url)
    else:
        raise ValueError(f"Unknown backend {session.backend}")

def handle_error(e: Exception) -> dict:
    logger.error(f"Error executing tool: {e}")
    return ErrorSchema(message=str(e), code="TOOL_ERROR").model_dump()

@mcp.tool()
def init_session(session_id: str, backend: str, binary_path: str, architecture: str, backend_url: str = "http://127.0.0.1:10101") -> str:
    """
    Initialize a new unified reverse engineering session.
    backend must be 'ida' or 'ghidra'.
    """
    try:
        session_manager.create_session(session_id, backend, binary_path, architecture, backend_url)
        return f"Session {session_id} successfully created."
    except Exception as e:
        return json.dumps(handle_error(e))

@mcp.tool()
async def get_function(session_id: str, address: str) -> Any:
    """Get complete details for a specific function."""
    try:
        adapter = get_adapter(session_id)
        func = await adapter.get_function(address)
        if func:
            return func.model_dump()
        return None
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def list_functions(session_id: str) -> Any:
    """List all functions in the current binary."""
    try:
        adapter = get_adapter(session_id)
        funcs = await adapter.list_functions()
        return [f.model_dump() for f in funcs]
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def decompile_function(session_id: str, address: str) -> Any:
    """Decompile a function at the given address."""
    try:
        adapter = get_adapter(session_id)
        code = await adapter.decompile_function(address)
        return {"decompiled": code}
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def get_xrefs(session_id: str, address: str) -> Any:
    """Get all cross-references to and from the given address."""
    try:
        adapter = get_adapter(session_id)
        xrefs = await adapter.get_xrefs(address)
        return [x.model_dump(by_alias=True) for x in xrefs]
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def get_strings(session_id: str) -> Any:
    """Extract strings from the binary."""
    try:
        adapter = get_adapter(session_id)
        strings = await adapter.get_strings()
        return [s.model_dump() for s in strings]
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def rename_symbol(session_id: str, address: str, name: str) -> Any:
    """Rename a symbol or function at the specified address."""
    try:
        adapter = get_adapter(session_id)
        success = await adapter.rename_symbol(address, name)
        return {"success": success}
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def batch_decompile(session_id: str, addresses: list[str]) -> Any:
    """Batch decompile multiple functions."""
    try:
        adapter = get_adapter(session_id)
        codes = await adapter.batch_decompile(addresses)
        return {"results": codes}
    except Exception as e:
        return handle_error(e)

@mcp.tool()
async def analyze_functions(session_id: str, addresses: list[str]) -> Any:
    """Trigger background analysis on a list of function addresses."""
    try:
        adapter = get_adapter(session_id)
        success = await adapter.analyze_functions(addresses)
        return {"success": success}
    except Exception as e:
        return handle_error(e)
