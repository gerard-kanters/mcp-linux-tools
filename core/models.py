"""Pydantic-modellen voor tool responses (outputSchema)."""

from typing import Any

from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    """Foutdetails in een tool-response."""

    code: str = Field(description="Error code, bijv. DENIED_PATH, INVALID_INPUT")
    message: str = Field(description="Leesbare foutmelding")
    hint: str | None = Field(default=None, description="Optionele herstelhint")


class MetaInfo(BaseModel):
    """Server-meta in elke tool-response."""

    server_type: str = Field(description="development of production")
    server_ip: str = Field(description="IP-adres van de server")
    server_name: str = Field(description="Naam van de MCP server")


class ToolResponse(BaseModel):
    """
    Uniform responsecontract voor alle MCP tools.

    success=True: data bevat het resultaat, error is None.
    success=False: error bevat code/message/hint, data is None.
    meta bevat altijd server-identificatie.
    """

    success: bool = Field(description="Of de operatie is gelukt")
    data: Any = Field(default=None, description="Resultaat bij succes (string, list, dict)")
    error: ErrorDetail | None = Field(default=None, description="Foutdetails bij falen")
    meta: MetaInfo = Field(description="Server-identificatie")
