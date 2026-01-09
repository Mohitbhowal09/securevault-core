import uuid
import time
from dataclasses import dataclass, asdict, field
from typing import Optional

@dataclass
class PasswordItem:
    site: str
    username: str
    secret: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: float = field(default_factory=time.time)
    type: str = "password"

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(data: dict) -> 'PasswordItem':
        # Safety: Ensure all required fields are present or handle defaults
        return PasswordItem(
            id=data.get('id', str(uuid.uuid4())),
            site=data.get('site', ''),
            username=data.get('username', ''),
            secret=data.get('secret', ''),
            created_at=data.get('created_at', time.time()),
            type=data.get('type', 'password')
        )
