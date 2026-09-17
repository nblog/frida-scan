#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Data models for frida-scan
"""

from typing import List, Dict, Literal, Optional
from pydantic import BaseModel, Field, ConfigDict, model_validator


# Keys used as ``addr[mode](match)`` in the embedded Frida scanner script.
ScanMode = Literal[
    "rva",
    "va",
    "imm8",
    "imm16",
    "imm32",
    "imm64",
    "imm128",
    "deref8",
    "deref16",
    "deref32",
    "deref64",
    "deref128",
    "rel32",
    "rel32CallTarget",
]


class ScanModel(BaseModel):
    """Base model that tolerates ``$``-prefixed metadata keys (e.g. ``$schema``, ``$usage``).

    Such keys are stripped before validation so self-documenting fields can
    live alongside the real config, while every other unknown key is still
    rejected by ``extra="forbid"``. JSON Schema mirrors that contract with
    ``patternProperties`` so editors accept the same metadata keys.
    """
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "patternProperties": {
                "^\\$": True,
            },
        },
    )

    @model_validator(mode="before")
    @classmethod
    def _strip_meta_keys(cls, data):
        if isinstance(data, dict):
            return {k: v for k, v in data.items()
                    if not (isinstance(k, str) and k.startswith("$"))}
        return data


class InsEqual(ScanModel):
    """Instruction equality check configuration.

    After a pattern match, walk instructions from the adjusted address until
    ``cmd`` is found or ``range`` bytes have been consumed.
    """
    cmd: str = Field(..., min_length=1, description="Instruction text to match (substring, case-insensitive)")
    range: int = Field(default=16, ge=0, description="Maximum number of bytes to search for the instruction")


class AobData(ScanModel):
    """Array of Bytes scan configuration.

    ``pattern`` is scanned in the target module; ``offset`` is evaluated and
    added to the selected match before ``mode`` reads the final value.
    """
    mode: ScanMode = Field(
        ...,
        description=(
            "How to interpret the match address: rva/va; "
            "imm8/16/32/64/128 (unsigned immediate); "
            "deref8/16/32/64/128 (dereference pointer then read); "
            "rel32 (x86 rel32 displacement field to target RVA); "
            "rel32CallTarget (CALL/JMP rel32 opcode E8/E9 to target RVA)"
        ),
    )
    pattern: str = Field(
        ...,
        min_length=1,
        description="Byte pattern to search for (space-separated hex; ``??`` wildcards cannot be the last byte)",
    )
    selected: int = Field(default=1, ge=1, description="Which match to select (1-based)")
    offset: str = Field(default="0", description="Offset expression evaluated from the match address")
    equal: Optional[InsEqual] = Field(default=None, description="Optional instruction equality check")


class PatternData(ScanModel):
    """Named scan result produced from an optional AOB chain.

    ``value`` is the fallback expression; the first successful AOB overwrites
    it. Pattern names are also identifiers in later expressions.
    """
    name: str = Field(
        ...,
        min_length=1,
        pattern=r"^[^#].*$",
        description="Pattern name (cannot start with ``#``, which is reserved)",
    )
    note: str = Field(default="", description="Pattern description")
    value: str = Field(default="0", description="Default value expression used when no AOB matches")
    aob: Optional[List[AobData]] = Field(default=None, description="AOB scan configurations; first success wins")


class ScanConfig(ScanModel):
    """Main scan configuration loaded from the JSON config file."""
    patterns: List[PatternData] = Field(..., min_length=1, description="List of patterns to scan")
    module: str = Field(default="", description="Target module name; empty uses the first loaded module")


class ScanResults(BaseModel):
    """Complete scan results"""
    results: Dict[str, int] = Field(default_factory=dict, description="Pattern name to value mapping")
    version: Optional[str] = Field(default=None, description="Target program version")

    model_config = ConfigDict(extra="forbid")
