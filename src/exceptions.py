#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Custom exceptions for frida-scan
"""


class FridaScanException(Exception):
    """Base exception for frida-scan operations"""
    pass


class ProcessNotFoundError(FridaScanException):
    """Raised when target process is not found"""
    pass


class ConfigurationError(FridaScanException):
    """Raised when configuration is invalid"""
    pass


class ScanError(FridaScanException):
    """Raised when scan operation fails"""
    pass
