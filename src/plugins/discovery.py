"""
Plugin discovery system for auto-loading plugins from individual folders.
"""

import importlib
import pkgutil
from pathlib import Path
from typing import Dict, List, Type

from loguru import logger

from .base import CapturePlugin


class PluginDiscovery:
    """Discovers and loads plugins from individual plugin folders."""

    def __init__(self, plugins_package: str = "src.plugins"):
        self.plugins_package = plugins_package
        self.discovered_plugins: Dict[str, Type[CapturePlugin]] = {}

    def discover_plugins(self) -> Dict[str, Type[CapturePlugin]]:
        """
        Discover all plugins by scanning plugin folders.

        Returns:
            Dictionary mapping protocol names to plugin classes
        """
        plugins_path = Path(__file__).parent

        # Scan for plugin directories
        for item in plugins_path.iterdir():
            if item.is_dir() and not item.name.startswith("__"):
                # Skip core plugin framework files
                if item.name in ["base", "registry", "manager", "tabbed_manager", "discovery"]:
                    continue

                plugin_name = item.name
                try:
                    plugin_class = self._load_plugin_from_folder(plugin_name)
                    if plugin_class:
                        # Get protocol name from plugin info
                        temp_instance = plugin_class({})
                        protocol = temp_instance.info.protocol
                        self.discovered_plugins[protocol] = plugin_class
                        logger.debug(f"Discovered plugin: {protocol} -> {plugin_class.__name__}")

                except Exception as e:
                    logger.warning(f"Failed to load plugin from folder '{plugin_name}': {e}")

        return self.discovered_plugins

    def _load_plugin_from_folder(self, folder_name: str) -> Type[CapturePlugin]:
        """
        Load a plugin class from a specific folder.

        Args:
            folder_name: Name of the plugin folder

        Returns:
            Plugin class or None if not found
        """
        try:
            # Try to import the plugin module
            module_name = f"{self.plugins_package}.{folder_name}"
            module = importlib.import_module(module_name)

            # Look for plugin classes that inherit from CapturePlugin
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, CapturePlugin)
                    and attr != CapturePlugin
                ):
                    return attr

            logger.warning(f"No CapturePlugin subclass found in {module_name}")
            return None

        except ImportError as e:
            logger.warning(f"Failed to import plugin module {module_name}: {e}")
            return None

    def get_plugin_info(self) -> Dict[str, Dict]:
        """Get information about all discovered plugins."""
        info = {}
        for protocol, plugin_class in self.discovered_plugins.items():
            try:
                temp_instance = plugin_class({})
                info[protocol] = temp_instance.info.dict()
            except Exception as e:
                logger.warning(f"Failed to get info for plugin {protocol}: {e}")
                info[protocol] = {"error": str(e)}

        return info

    def list_plugin_folders(self) -> List[str]:
        """List all plugin folders found."""
        plugins_path = Path(__file__).parent
        folders = []

        for item in plugins_path.iterdir():
            if (
                item.is_dir()
                and not item.name.startswith("__")
                and item.name not in ["base", "registry", "manager", "tabbed_manager", "discovery"]
            ):
                folders.append(item.name)

        return folders
