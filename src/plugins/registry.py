"""
Global plugin registry instance with auto-discovery.
"""

from .base import PluginRegistry
from .discovery import PluginDiscovery

# Global plugin registry instance
plugin_registry = PluginRegistry()

# Auto-discover and register plugins
discovery = PluginDiscovery()
discovered_plugins = discovery.discover_plugins()

for protocol, plugin_class in discovered_plugins.items():
    try:
        plugin_registry.register(plugin_class)
    except Exception as e:
        from loguru import logger

        logger.warning(f"Failed to register plugin {protocol}: {e}")
