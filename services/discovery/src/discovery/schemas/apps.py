"""Pydantic v2 schemas for Application resources."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CreateAppRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=128)
    owner: Optional[str] = Field(None, max_length=256)

    @field_validator("name", "owner", mode="before")
    @classmethod
    def _strip_and_reject_nullbytes(cls, v: object) -> object:
        if isinstance(v, str):
            v = v.strip()
            if "\x00" in v:
                raise ValueError("Null bytes are not permitted")
        return v


class UpdateAppRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = Field(None, min_length=1, max_length=128)
    owner: Optional[str] = Field(None, max_length=256)

    @field_validator("name", "owner", mode="before")
    @classmethod
    def _strip_and_reject_nullbytes(cls, v: object) -> object:
        if isinstance(v, str):
            v = v.strip()
            if "\x00" in v:
                raise ValueError("Null bytes are not permitted")
        return v


class AppResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    owner: Optional[str]
    is_active: bool
    created_at: Optional[datetime]
    updated_at: Optional[datetime]


class AppListResponse(BaseModel):
    items: list[AppResponse]
    total_count: int
    next_cursor: Optional[str]
