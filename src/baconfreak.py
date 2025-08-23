#!/usr/bin/env python3
"""
BLE and WiFi packet analysis tool using plugin framework.

This module coordinates capture operations through the plugin manager.
"""

import sys
from typing import Any, Dict, Optional

from rich.console import Console

from .config import config
from .logger import setup_logging
from .plugins.manager import PluginManager


def main(
    protocol: str = "ble",
    interface: Optional[int] = None,
    enable_ui: bool = True,
    quiet: bool = False,
    **kwargs: Any,
) -> None:
    """
    Main entry point for packet capture using plugin framework.
    
    Args:
        protocol: Protocol to capture ('ble' or 'wifi')
        interface: Interface number to use
        enable_ui: Enable Rich UI
        quiet: Quiet mode
        **kwargs: Additional configuration options
    """
    # Setup logging
    setup_logging(debug=kwargs.get("debug", False), quiet=quiet)
    
    # Create console
    console = Console() if enable_ui else None
    
    # Create plugin manager
    manager = PluginManager(console)
    
    try:
        # Prepare plugin configuration
        plugin_config = {
            "interface": interface or config.scan_config.interface,
            "quiet": quiet,
            "enable_ui": enable_ui,
            **kwargs
        }
        
        # Create and start plugin
        plugin = manager.create_plugin(protocol, plugin_config)
        manager.start_capture(plugin, enable_ui=enable_ui, quiet=quiet)
        
    except KeyboardInterrupt:
        if not quiet and console:
            console.print("\n🛑 [yellow]Interrupted by user[/yellow]")
    except Exception as e:
        if console:
            console.print(f"❌ [red]Error: {e}[/red]")
        else:
            print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()