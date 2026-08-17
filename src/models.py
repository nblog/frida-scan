#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Data models for frida-scan
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field, ConfigDict, model_validator


class ScanModel(BaseModel):
    """Base model that tolerates ``$``-prefixed metadata keys (e.g. ``$usage``).

    Such keys are stripped before validation so self-documenting fields can
    live alongside the real config, while every other unknown key is still
    rejected by ``extra="forbid"``.
    """
    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def _strip_meta_keys(cls, data):
        if isinstance(data, dict):
            return {k: v for k, v in data.items()
                    if not (isinstance(k, str) and k.startswith("$"))}
        return data


class InsEqual(ScanModel):
    """Instruction equality check configuration"""
    cmd: str = Field(..., description="Instruction command to match")
    range: int = Field(default=16, description="Range to search for instruction")
    
    model_config = ConfigDict(extra="forbid")


class AobData(ScanModel):
    """Array of Bytes scan configuration"""
    mode: str = Field(..., description="Scan mode: rva, va, imm8, imm16, imm32, imm64, mem32, call")
    pattern: str = Field(..., description="Byte pattern to search for")
    selected: Optional[int] = Field(default=1, description="Which match to select (1-based)")
    offset: Optional[str] = Field(default="0", description="Offset expression")
    equal: Optional[InsEqual] = Field(default=None, description="Instruction equality check")
    
    model_config = ConfigDict(extra="forbid")


class PatternData(ScanModel):
    """Pattern configuration for scanning"""
    name: str = Field(..., description="Pattern name")
    note: Optional[str] = Field(default="", description="Pattern description")
    value: Optional[str] = Field(default="0", description="Default value expression")
    aob: Optional[List[AobData]] = Field(default=None, description="AOB scan configurations")
    
    model_config = ConfigDict(extra="forbid")


class ScanConfig(ScanModel):
    """Main scan configuration"""
    patterns: List[PatternData] = Field(..., description="List of patterns to scan")
    module: Optional[str] = Field(default="", description="Target module name")
    
    model_config = ConfigDict(extra="forbid")


class ScanResults(BaseModel):
    """Complete scan results"""
    results: Dict[str, int] = Field(default_factory=dict, description="Pattern name to value mapping")
    version: Optional[str] = Field(default=None, description="Target program version")
    
    model_config = ConfigDict(extra="forbid")
