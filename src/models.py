#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Data models for frida-scan
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field, ConfigDict


class InsEqual(BaseModel):
    """Instruction equality check configuration"""
    cmd: str = Field(..., description="Instruction command to match")
    range: int = Field(default=16, description="Range to search for instruction")
    
    model_config = ConfigDict(extra="forbid")


class AobData(BaseModel):
    """Array of Bytes scan configuration"""
    mode: str = Field(..., description="Scan mode: rva, va, imm8, imm16, imm32, imm64, mem32, call")
    pattern: str = Field(..., description="Byte pattern to search for")
    selected: Optional[int] = Field(default=1, description="Which match to select (1-based)")
    offset: Optional[str] = Field(default="0", description="Offset expression")
    equal: Optional[InsEqual] = Field(default=None, description="Instruction equality check")
    
    model_config = ConfigDict(extra="forbid")


class PatternData(BaseModel):
    """Pattern configuration for scanning"""
    name: str = Field(..., description="Pattern name")
    note: Optional[str] = Field(default="", description="Pattern description")
    value: Optional[str] = Field(default="0", description="Default value expression")
    aob: Optional[List[AobData]] = Field(default=None, description="AOB scan configurations")
    
    model_config = ConfigDict(extra="forbid")


class ScanConfig(BaseModel):
    """Main scan configuration"""
    patterns: List[PatternData] = Field(..., description="List of patterns to scan")
    module: Optional[str] = Field(default="", description="Target module name")
    
    model_config = ConfigDict(extra="forbid")


class ScanResult(BaseModel):
    """Scan result data"""
    name: str = Field(..., description="Pattern name")
    value: int = Field(..., description="Found address/value")
    note: Optional[str] = Field(default="", description="Pattern note")
    
    model_config = ConfigDict(extra="forbid")


class ScanResults(BaseModel):
    """Complete scan results"""
    results: Dict[str, int] = Field(default_factory=dict, description="Pattern name to value mapping")
    version: Optional[str] = Field(default=None, description="Target program version")
    
    model_config = ConfigDict(extra="forbid")
