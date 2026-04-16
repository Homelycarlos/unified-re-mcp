from typing import List, Optional
import aiohttp
from .base import BaseAdapter
from schemas.models import (
    FunctionSchema, StringSchema, XrefSchema,
    InstructionSchema, CommentSchema, GlobalVarSchema,
    SegmentSchema, ImportSchema, ExportSchema
)

class IDAAdapter(BaseAdapter):
    """
    Adapter mapping unified MCP tool calls to the IDA Pro background
    HTTP server (ida_backend_plugin.py) running on the local machine.
    All calls are dispatched as JSON POST requests with an 'action' key.
    """
    def __init__(self, backend_url: str):
        self.base_url = backend_url

    async def _call(self, action: str, args: dict = None) -> dict:
        """Issue a single JSON POST to the IDA background HTTP server."""
        payload = {"action": action, "args": args or {}}
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{self.base_url}/rpc", json=payload) as resp:
                resp.raise_for_status()
                return await resp.json()

    # ── Decompilation & Function Listing ──────────────────────────────────

    async def list_functions(self) -> List[FunctionSchema]:
        res = await self._call("get_functions")
        return [
            FunctionSchema(
                name=f.get('name', ''),
                address=f.get('address', ''),
                size=f.get('size', 0),
                instructions=[],
                decompiled=None,
                xrefs=[]
            ) for f in res.get("functions", [])
        ]

    async def get_function(self, address: str) -> Optional[FunctionSchema]:
        res = await self._call("get_function", {"address": address})
        if not res or "error" in res:
            return None
        return FunctionSchema(
            name=res.get('name', ''),
            address=res.get('address', address),
            size=res.get('size', 0),
            instructions=[],
            decompiled=None,
            xrefs=[]
        )

    async def decompile_function(self, address: str) -> Optional[str]:
        res = await self._call("decompile", {"address": address})
        return res.get("code")

    async def disassemble_at(self, address: str) -> List[InstructionSchema]:
        res = await self._call("disassemble", {"address": address})
        raw = res.get("code", "")
        instructions = []
        for line in raw.split("\n"):
            line = line.strip()
            if not line:
                continue
            # Lines are formatted as "0xADDR: mnemonic operands"
            if ": " in line:
                addr_part, rest = line.split(": ", 1)
                parts = rest.split(None, 1)
                mnem = parts[0] if parts else rest
                ops = parts[1] if len(parts) > 1 else ""
                instructions.append(InstructionSchema(
                    address=addr_part, mnemonic=mnem, operands=ops, raw_line=line
                ))
            else:
                instructions.append(InstructionSchema(
                    address="", mnemonic=line, operands="", raw_line=line
                ))
        return instructions

    async def batch_decompile(self, addresses: List[str]) -> List[str]:
        out = []
        for addr in addresses:
            code = await self.decompile_function(addr)
            if code:
                out.append(code)
        return out

    async def analyze_functions(self, addresses: List[str]) -> bool:
        res = await self._call("analyze_functions", {"addresses": addresses})
        return res.get("success", False)

    # ── Cross-References ──────────────────────────────────────────────────

    async def get_xrefs(self, address: str) -> List[XrefSchema]:
        res = await self._call("get_xrefs", {"address": address})
        xrefs_data = res.get("xrefs", {})
        results = []
        for ref in xrefs_data.get("to", []):
            results.append(XrefSchema(from_addr=ref, to_addr=address, type="CodeTo"))
        for ref in xrefs_data.get("from", []):
            results.append(XrefSchema(from_addr=address, to_addr=ref, type="CodeFrom"))
        return results

    # ── Data & Strings ────────────────────────────────────────────────────

    async def get_strings(self) -> List[StringSchema]:
        res = await self._call("get_strings")
        return [StringSchema(**s) for s in res.get("strings", [])]

    async def get_globals(self) -> List[GlobalVarSchema]:
        res = await self._call("get_globals")
        return [GlobalVarSchema(**g) for g in res.get("globals", [])]

    async def get_segments(self) -> List[SegmentSchema]:
        res = await self._call("get_segments")
        return [SegmentSchema(**s) for s in res.get("segments", [])]

    async def get_imports(self) -> List[ImportSchema]:
        res = await self._call("get_imports")
        return [ImportSchema(**i) for i in res.get("imports", [])]

    async def get_exports(self) -> List[ExportSchema]:
        res = await self._call("get_exports")
        return [ExportSchema(**e) for e in res.get("exports", [])]

    # ── Modification ──────────────────────────────────────────────────────

    async def rename_symbol(self, address: str, name: str) -> bool:
        res = await self._call("rename", {"address": address, "name": name})
        return res.get("success", False)

    async def set_comment(self, address: str, comment: str, repeatable: bool = False) -> bool:
        res = await self._call("set_comment", {"address": address, "comment": comment, "repeatable": repeatable})
        return res.get("success", False)

    async def set_function_type(self, address: str, signature: str) -> bool:
        res = await self._call("set_function_type", {"address": address, "signature": signature})
        return res.get("success", False)
