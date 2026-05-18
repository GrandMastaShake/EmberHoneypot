"""
Interaction log models.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class InteractionType(str, Enum):
    COMMAND = "command"
    QUERY = "query"
    FILE_ACCESS = "file_access"
    NETWORK = "network"
    LOGIN = "login"


class FileAction(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"


class ParsedCommand(BaseModel):
    binary: str
    arguments: list[str] = Field(default_factory=list)
    flags: dict[str, str | None] = Field(default_factory=dict)
    pipe_chain: list[str] = Field(default_factory=list)
    redirections: list[str] = Field(default_factory=list)


class InteractionLog(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    session_id: UUID
    attacker_id: UUID
    honeypot_id: UUID

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sequence_number: int = 0
    response_time_ms: int = 0

    interaction_type: InteractionType = InteractionType.COMMAND
    raw_input: str = ""
    raw_output: str = ""
    parsed_command: ParsedCommand | None = None

    working_directory: str | None = None
    user_context: str | None = None
    environment: dict[str, str] = Field(default_factory=dict)

    source_ip: str = ""
    source_port: int = 0
    destination_port: int = 0