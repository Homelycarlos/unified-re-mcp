import abc
from typing import List, Optional
from schemas.models import (
    FunctionSchema, StringSchema, XrefSchema,
    InstructionSchema, CommentSchema, GlobalVarSchema,
    SegmentSchema, ImportSchema, ExportSchema
)

class BaseAdapter(abc.ABC):
    """
    Abstract interface guaranteeing all tool implementations are pure functions
    that return normalized deterministic schemas.
    """

    # ── Decompilation & Function Listing ──────────────────────────────────

    @abc.abstractmethod
    async def list_functions(self) -> List[FunctionSchema]:
        pass

    @abc.abstractmethod
    async def get_function(self, address: str) -> Optional[FunctionSchema]:
        pass

    @abc.abstractmethod
    async def decompile_function(self, address: str) -> Optional[str]:
        pass

    @abc.abstractmethod
    async def disassemble_at(self, address: str) -> List[InstructionSchema]:
        """Disassemble the function or block at the given address."""
        pass

    @abc.abstractmethod
    async def batch_decompile(self, addresses: List[str]) -> List[str]:
        pass

    @abc.abstractmethod
    async def analyze_functions(self, addresses: List[str]) -> bool:
        pass

    # ── Cross-References ──────────────────────────────────────────────────

    @abc.abstractmethod
    async def get_xrefs(self, address: str) -> List[XrefSchema]:
        pass

    # ── Data & Strings ────────────────────────────────────────────────────

    @abc.abstractmethod
    async def get_strings(self) -> List[StringSchema]:
        pass

    @abc.abstractmethod
    async def get_globals(self) -> List[GlobalVarSchema]:
        """Get global data items from the binary."""
        pass

    @abc.abstractmethod
    async def get_segments(self) -> List[SegmentSchema]:
        """Get memory segments."""
        pass

    @abc.abstractmethod
    async def get_imports(self) -> List[ImportSchema]:
        """Get imported symbols."""
        pass

    @abc.abstractmethod
    async def get_exports(self) -> List[ExportSchema]:
        """Get exported symbols."""
        pass

    # ── Modification ──────────────────────────────────────────────────────

    @abc.abstractmethod
    async def rename_symbol(self, address: str, name: str) -> bool:
        pass

    @abc.abstractmethod
    async def set_comment(self, address: str, comment: str, repeatable: bool = False) -> bool:
        """Set a comment at the given address."""
        pass

    @abc.abstractmethod
    async def set_function_type(self, address: str, signature: str) -> bool:
        """Apply a C function prototype to the function at address."""
        pass
