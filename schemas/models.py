from typing import List, Optional
from pydantic import BaseModel, Field

class FunctionSchema(BaseModel):
    name: str
    address: str
    size: int
    instructions: List[str]
    decompiled: Optional[str] = None
    xrefs: List[str]

class StringSchema(BaseModel):
    address: str
    value: str

class XrefSchema(BaseModel):
    from_addr: str = Field(alias="from")
    to_addr: str = Field(alias="to")
    type: str

    class Config:
        populate_by_name = True

class ErrorSchema(BaseModel):
    error: bool = True
    message: str
    code: str
