"""
Utility functions shared across the baconfreak codebase.

This module provides common utilities for formatting, validation, and data processing
that are used across multiple plugins and components.
"""

from datetime import timedelta
from typing import Tuple, Union


def format_time_delta(delta: Union[timedelta, float]) -> str:
    """
    Format timedelta to human readable string.
    
    Args:
        delta: Either a timedelta object or total seconds as float
        
    Returns:
        Formatted time string (e.g., "2m", "1h30m", "2d5h")
    """
    if isinstance(delta, timedelta):
        total_seconds = int(delta.total_seconds())
    else:
        total_seconds = int(delta)
    
    if total_seconds < 60:
        return f"{total_seconds}s"
    elif total_seconds < 3600:
        minutes = total_seconds // 60
        return f"{minutes}m"
    elif total_seconds < 86400:
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        return f"{hours}h{minutes}m" if minutes > 0 else f"{hours}h"
    else:
        days = total_seconds // 86400
        hours = (total_seconds % 86400) // 3600
        return f"{days}d{hours}h" if hours > 0 else f"{days}d"


def normalize_mac_address(mac: str) -> str:
    """
    Normalize MAC address to standard format.
    
    Args:
        mac: MAC address string in various formats
        
    Returns:
        Normalized MAC address in lowercase with colons
    """
    # Remove common separators and normalize
    cleaned = mac.replace("-", "").replace(":", "").replace(".", "").lower()
    
    # Validate length
    if len(cleaned) != 12:
        raise ValueError(f"Invalid MAC address length: {mac}")
    
    # Validate hex characters
    try:
        int(cleaned, 16)
    except ValueError:
        raise ValueError(f"Invalid MAC address format: {mac}")
    
    # Format with colons
    return ":".join(cleaned[i:i+2] for i in range(0, 12, 2))


def format_rssi_with_quality(rssi: int) -> Tuple[str, str]:
    """
    Format RSSI value with quality indicator.
    
    Args:
        rssi: RSSI value in dBm
        
    Returns:
        Tuple of (formatted_value, quality_style)
    """
    if rssi > -50:
        return f"{rssi}", "green"
    elif rssi > -70:
        return f"{rssi}", "yellow"
    else:
        return f"{rssi}", "red"


def truncate_string(text: str, max_length: int, suffix: str = "...") -> str:
    """
    Truncate string to maximum length with suffix.
    
    Args:
        text: String to truncate
        max_length: Maximum allowed length including suffix
        suffix: Suffix to add when truncating
        
    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


__all__ = [
    "format_time_delta",
    "normalize_mac_address", 
    "format_rssi_with_quality",
    "truncate_string",
]