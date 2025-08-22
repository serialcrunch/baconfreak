"""
Base classes and interfaces for the plugin framework.
"""

import abc
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, Union

from pydantic import BaseModel, Field
from rich.console import Console
from rich.layout import Layout

from ..models import DeviceStats


class PluginInfo(BaseModel):
    """Information about a plugin."""
    
    name: str = Field(..., description="Plugin name")
    version: str = Field(..., description="Plugin version")
    description: str = Field(..., description="Plugin description")
    protocol: str = Field(..., description="Network protocol (e.g., 'ble', 'wifi')")
    requires_root: bool = Field(True, description="Whether plugin requires root privileges")
    supported_platforms: List[str] = Field(default_factory=lambda: ["linux"], description="Supported platforms")
    config_schema: Optional[Dict[str, Any]] = Field(None, description="Configuration schema")


class CapturePlugin(abc.ABC):
    """
    Abstract base class for capture plugins.
    
    Each plugin implements a specific network capture protocol (BLE, WiFi, etc.)
    and provides unified interfaces for scanning, device detection, and data export.
    """
    
    def __init__(self, config: Dict[str, Any], console: Optional[Console] = None):
        """
        Initialize the plugin.
        
        Args:
            config: Plugin-specific configuration
            console: Rich console for output (optional)
        """
        self.config = config
        self.console = console or Console()
        self.devices: Dict[str, Any] = {}
        self.stats = DeviceStats()
        self._running = False
        self._session_timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    
    @property
    @abc.abstractmethod
    def info(self) -> PluginInfo:
        """Return plugin information."""
        pass
    
    @property
    def session_timestamp(self) -> str:
        """Get the session timestamp for file naming."""
        return self._session_timestamp
    
    @property
    def is_running(self) -> bool:
        """Check if plugin is currently running."""
        return self._running
    
    @abc.abstractmethod
    def validate_config(self) -> tuple[bool, List[str]]:
        """
        Validate plugin configuration.
        
        Returns:
            Tuple of (is_valid, error_messages)
        """
        pass
    
    @abc.abstractmethod
    def check_requirements(self) -> tuple[bool, List[str]]:
        """
        Check if system requirements are met.
        
        Returns:
            Tuple of (requirements_met, error_messages)
        """
        pass
    
    @abc.abstractmethod
    def get_default_output_files(self, output_dir: Path) -> Dict[str, Path]:
        """
        Get default output file paths for this plugin.
        
        Args:
            output_dir: Base output directory
            
        Returns:
            Dictionary mapping file type to path
        """
        pass
    
    @abc.abstractmethod
    def initialize_capture(self) -> None:
        """
        Initialize capture interfaces and resources.
        
        Raises:
            PluginError: If initialization fails
        """
        pass
    
    @abc.abstractmethod
    def start_capture(self, packet_callback, stop_event) -> None:
        """
        Start packet capture.
        
        Args:
            packet_callback: Function to call for each captured packet
            stop_event: Threading event to signal stop
        """
        pass
    
    @abc.abstractmethod
    def stop_capture(self) -> None:
        """Stop packet capture and cleanup resources."""
        pass
    
    @abc.abstractmethod
    def process_packet(self, packet: Any) -> Optional[Dict[str, Any]]:
        """
        Process a captured packet and extract device information.
        
        Args:
            packet: Raw packet data
            
        Returns:
            Device information dictionary or None if packet should be ignored
        """
        pass
    
    @abc.abstractmethod
    def create_live_display(self) -> Layout:
        """Create Rich live display layout for this plugin."""
        pass
    
    @abc.abstractmethod
    def update_display(self, layout: Layout) -> None:
        """Update the live display with current data."""
        pass
    
    @abc.abstractmethod
    def get_statistics(self) -> Dict[str, Any]:
        """Get plugin-specific statistics."""
        pass
    
    def get_timestamped_filename(self, base_filename: str) -> str:
        """Generate a timestamped filename with plugin prefix."""
        path = Path(base_filename)
        stem = path.stem
        suffix = path.suffix
        plugin_name = self.info.protocol.upper()
        return f"{plugin_name}-{self.session_timestamp}-{stem}{suffix}"


class PluginRegistry:
    """Registry for managing capture plugins."""
    
    def __init__(self):
        self._plugins: Dict[str, Type[CapturePlugin]] = {}
        self._instances: Dict[str, CapturePlugin] = {}
    
    def register(self, plugin_class: Type[CapturePlugin]) -> None:
        """
        Register a plugin class.
        
        Args:
            plugin_class: Plugin class to register
        """
        # Create temporary instance to get info
        temp_instance = plugin_class({})
        protocol = temp_instance.info.protocol
        
        if protocol in self._plugins:
            raise ValueError(f"Plugin for protocol '{protocol}' already registered")
        
        self._plugins[protocol] = plugin_class
    
    def get_plugin_class(self, protocol: str) -> Optional[Type[CapturePlugin]]:
        """
        Get plugin class by protocol name.
        
        Args:
            protocol: Protocol name (e.g., 'ble', 'wifi')
            
        Returns:
            Plugin class or None if not found
        """
        return self._plugins.get(protocol)
    
    def create_plugin(self, protocol: str, config: Dict[str, Any], 
                     console: Optional[Console] = None) -> Optional[CapturePlugin]:
        """
        Create plugin instance.
        
        Args:
            protocol: Protocol name
            config: Plugin configuration
            console: Rich console instance
            
        Returns:
            Plugin instance or None if protocol not found
        """
        plugin_class = self.get_plugin_class(protocol)
        if not plugin_class:
            return None
        
        if protocol in self._instances:
            # Return existing instance
            return self._instances[protocol]
        
        instance = plugin_class(config, console)
        self._instances[protocol] = instance
        return instance
    
    def list_protocols(self) -> List[str]:
        """Get list of registered protocol names."""
        return list(self._plugins.keys())
    
    def get_plugin_info(self, protocol: str) -> Optional[PluginInfo]:
        """
        Get plugin information.
        
        Args:
            protocol: Protocol name
            
        Returns:
            Plugin info or None if not found
        """
        plugin_class = self.get_plugin_class(protocol)
        if not plugin_class:
            return None
        
        # Cache plugin info to avoid creating temporary instances repeatedly
        if not hasattr(self, '_plugin_info_cache'):
            self._plugin_info_cache = {}
        
        if protocol not in self._plugin_info_cache:
            temp_instance = plugin_class({})
            self._plugin_info_cache[protocol] = temp_instance.info
        
        return self._plugin_info_cache[protocol]
    
    def list_all_plugins(self) -> Dict[str, PluginInfo]:
        """Get information for all registered plugins."""
        return {
            protocol: self.get_plugin_info(protocol)
            for protocol in self.list_protocols()
        }


class PluginError(Exception):
    """Base exception for plugin errors."""
    
    def __init__(self, message: str, plugin_name: Optional[str] = None, 
                 details: Optional[Dict[str, Any]] = None):
        """
        Initialize plugin error.
        
        Args:
            message: Error message
            plugin_name: Name of the plugin that caused the error
            details: Additional error details
        """
        super().__init__(message)
        self.plugin_name = plugin_name
        self.details = details or {}


class PluginConfigError(PluginError):
    """Raised when plugin configuration is invalid."""
    pass


class PluginRequirementError(PluginError):
    """Raised when plugin requirements are not met."""
    pass


class PluginInterfaceError(PluginError):
    """Raised when plugin interface is not available or accessible."""
    pass