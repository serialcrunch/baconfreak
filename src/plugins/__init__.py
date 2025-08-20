"""
Plugin framework for baconfreak.

This module provides the core plugin architecture that allows baconfreak to support
different network capture protocols (BLE, WiFi, etc.) through a pluggable interface.

Plugins are automatically discovered from individual folders within this package.
Each plugin should be in its own folder with a plugin.py file containing a 
CapturePlugin subclass.
"""

from .base import CapturePlugin, PluginInfo, PluginRegistry
from .registry import plugin_registry  # Auto-discovery happens here
from .manager import PluginManager
from .tabbed_manager import TabbedPluginManager
from .discovery import PluginDiscovery

# Import plugin classes for backward compatibility
try:
    from .ble import BLEPlugin
    from .wifi import WiFiPlugin
except ImportError:
    # Plugins may not be available in all environments
    BLEPlugin = None
    WiFiPlugin = None

__all__ = [
    "CapturePlugin", 
    "PluginInfo", 
    "PluginRegistry", 
    "PluginManager", 
    "TabbedPluginManager",
    "PluginDiscovery",
    "plugin_registry"
]

# Add plugin classes if available
if BLEPlugin:
    __all__.append("BLEPlugin")
if WiFiPlugin:
    __all__.append("WiFiPlugin")