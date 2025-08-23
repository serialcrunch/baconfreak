"""
Common exception classes for BaconFreak.
"""


class BaconFreakError(Exception):
    """Base exception for all BaconFreak errors."""


class BaconFreakPermissionError(BaconFreakError):
    """Raised when insufficient permissions for operations."""


class BaconFreakInterfaceError(BaconFreakError):
    """Raised when interface is not available."""