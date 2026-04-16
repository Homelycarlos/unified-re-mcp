import abc
from typing import List, Optional
from schemas.models import FunctionSchema, StringSchema, XrefSchema

class BaseAdapter(abc.ABC):
    """
    Abstract interface guaranteeing all tool implementations are pure functions
    that return normalized deterministic schemas.
    """
    
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
    async def get_xrefs(self, address: str) -> List[XrefSchema]:
        pass

    @abc.abstractmethod
    async def get_strings(self) -> List[StringSchema]:
        pass

    @abc.abstractmethod
    async def rename_symbol(self, address: str, name: str) -> bool:
        pass

    @abc.abstractmethod
    async def batch_decompile(self, addresses: List[str]) -> List[str]:
        pass

    @abc.abstractmethod
    async def analyze_functions(self, addresses: List[str]) -> bool:
        pass
