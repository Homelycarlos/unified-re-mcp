from typing import List, Optional
import aiohttp
from .base import BaseAdapter
from schemas.models import FunctionSchema, StringSchema, XrefSchema

class GhidraAdapter(BaseAdapter):
    """
    Example Wrapper mapping normalized functions to GhidraMCP background endpoints.
    """
    def __init__(self, backend_url: str):
        self.base_url = backend_url

    async def _rpc_call(self, method: str, params: dict) -> dict:
        async with aiohttp.ClientSession() as session:
            payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
            async with session.post(f"{self.base_url}/rpc", json=payload) as resp:
                resp.raise_for_status()
                data = await resp.json()
                if "error" in data:
                    raise Exception(data["error"])
                return data.get("result", {})

    async def list_functions(self) -> List[FunctionSchema]:
        res = await self._rpc_call("ghidra_list_functions", {})
        return [
            FunctionSchema(
                name=f.get('name', ''),
                address=f.get('address', ''),
                size=f.get('size', 0),
                instructions=f.get('instructions', []),
                decompiled=None,
                xrefs=[]
            ) for f in res.get("functions", [])
        ]

    async def get_function(self, address: str) -> Optional[FunctionSchema]:
        res = await self._rpc_call("ghidra_get_function", {"address": address})
        if not res:
            return None
        return FunctionSchema(**res)

    async def decompile_function(self, address: str) -> Optional[str]:
        res = await self._rpc_call("ghidra_decompile_function", {"address": address})
        return res.get("code")

    async def get_xrefs(self, address: str) -> List[XrefSchema]:
        res = await self._rpc_call("ghidra_get_xrefs", {"address": address})
        xrefs = []
        for x in res.get("xrefs", []):
            xrefs.append(XrefSchema(from_addr=x.get("from"), to_addr=x.get("to"), type=x.get("type", "Code")))
        return xrefs

    async def get_strings(self) -> List[StringSchema]:
        res = await self._rpc_call("ghidra_get_strings", {})
        return [StringSchema(**s) for s in res.get("strings", [])]

    async def rename_symbol(self, address: str, name: str) -> bool:
        res = await self._rpc_call("ghidra_rename_symbol", {"address": address, "name": name})
        return res.get("success", False)

    async def batch_decompile(self, addresses: List[str]) -> List[str]:
        out = []
        for addr in addresses:
            code = await self.decompile_function(addr)
            if code:
                out.append(code)
        return out

    async def analyze_functions(self, addresses: List[str]) -> bool:
        res = await self._rpc_call("ghidra_analyze_functions", {"addresses": addresses})
        return res.get("success", False)
