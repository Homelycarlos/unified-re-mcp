from typing import Dict, Any, Optional
from pydantic import BaseModel

class SessionState(BaseModel):
    backend: str  # "ida" or "ghidra"
    binary_path: str
    architecture: str
    backend_url: str = "http://127.0.0.1:10101" # Default connection url for the backend adapter

class SessionManager:
    """
    STRICT stateless session manager.
    Zero global state leakage. Everything is scoped to session_id.
    """
    def __init__(self):
        self._sessions: Dict[str, SessionState] = {}

    def create_session(self, session_id: str, backend: str, binary_path: str, architecture: str, backend_url: str = "http://127.0.0.1:10101") -> SessionState:
        if backend not in ["ida", "ghidra"]:
            raise ValueError(f"Unsupported backend {backend}")
            
        state = SessionState(
            backend=backend,
            binary_path=binary_path,
            architecture=architecture,
            backend_url=backend_url
        )
        self._sessions[session_id] = state
        return state

    def get_session(self, session_id: str) -> Optional[SessionState]:
        return self._sessions.get(session_id)

    def delete_session(self, session_id: str) -> bool:
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False
