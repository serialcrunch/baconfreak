#!/usr/bin/env python3
"""
Example script showing how to create a custom plugin for baconfreak.

This creates a simple demo plugin that doesn't actually capture packets,
but demonstrates the plugin interface and auto-discovery system.
"""

import os
import sys
from pathlib import Path

# Demo plugin code
DEMO_PLUGIN_CODE = '''"""
Demo plugin for baconfreak - Example implementation.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table

from ..base import CapturePlugin, PluginInfo


class DemoPlugin(CapturePlugin):
    """Demo plugin that simulates packet capture for demonstration purposes."""
    
    def __init__(self, config: Dict[str, Any], console: Optional[Console] = None):
        super().__init__(config, console)
        
        # Demo-specific configuration
        self.interface = config.get("interface", "demo0")
        self.scan_timeout = config.get("scan_timeout", 0)
        self.packet_rate = config.get("packet_rate", 10)  # packets per second
        
        # Demo state
        self.demo_devices = {}
        self.packet_counter = 0
    
    @property
    def info(self) -> PluginInfo:
        """Return demo plugin information."""
        return PluginInfo(
            name="Demo Scanner",
            version="1.0.0",
            description="Demonstration plugin that simulates packet capture",
            protocol="demo",
            requires_root=False,
            supported_platforms=["linux", "darwin", "win32"],
            config_schema={
                "interface": {"type": "string", "default": "demo0", "description": "Demo interface name"},
                "scan_timeout": {"type": "integer", "default": 0, "description": "Scan timeout (0=infinite)"},
                "packet_rate": {"type": "integer", "default": 10, "description": "Simulated packets per second"}
            }
        )
    
    def validate_config(self) -> tuple[bool, List[str]]:
        """Validate demo plugin configuration."""
        errors = []
        
        if not isinstance(self.interface, str) or not self.interface:
            errors.append("interface must be a non-empty string")
        
        if not isinstance(self.scan_timeout, int) or self.scan_timeout < 0:
            errors.append("scan_timeout must be a non-negative integer")
        
        if not isinstance(self.packet_rate, int) or self.packet_rate <= 0:
            errors.append("packet_rate must be a positive integer")
        
        return len(errors) == 0, errors
    
    def check_requirements(self) -> tuple[bool, List[str]]:
        """Check demo plugin requirements."""
        # Demo plugin has no special requirements
        return True, []
    
    def get_default_output_files(self, output_dir: Path) -> Dict[str, Path]:
        """Get default demo output file paths."""
        return {
            "demo_packets": output_dir / self.get_timestamped_filename("demo-packets.pcap"),
            "demo_devices": output_dir / self.get_timestamped_filename("demo-devices.json")
        }
    
    def initialize_capture(self) -> None:
        """Initialize demo capture."""
        self.console.print(f"[green]Demo plugin initialized on interface {self.interface}[/green]")
    
    def start_capture(self, packet_callback, stop_event) -> None:
        """Start demo packet simulation."""
        import time
        
        self._running = True
        
        while self._running and not stop_event.is_set():
            # Simulate packet capture
            self.packet_counter += 1
            
            # Create fake device every 10 packets
            if self.packet_counter % 10 == 0:
                device_id = f"demo_device_{len(self.demo_devices) + 1}"
                self.demo_devices[device_id] = {
                    "first_seen": datetime.now(),
                    "last_seen": datetime.now(),
                    "packet_count": 1
                }
            
            self.stats.total_packets += 1
            self.stats.valid_packets += 1
            
            # Simulate packet processing time
            time.sleep(1.0 / self.packet_rate)
    
    def stop_capture(self) -> None:
        """Stop demo capture."""
        self._running = False
        self.console.print("[yellow]Demo plugin stopped[/yellow]")
    
    def process_packet(self, packet: Any) -> Optional[Dict[str, Any]]:
        """Process demo packet."""
        return {
            "type": "demo",
            "packet_id": self.packet_counter,
            "timestamp": datetime.now()
        }
    
    def create_live_display(self) -> Layout:
        """Create demo live display layout."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        layout["main"].split_row(
            Layout(name="devices", ratio=2),
            Layout(name="stats", ratio=1)
        )
        return layout
    
    def update_display(self, layout: Layout) -> None:
        """Update demo live display."""
        # Header
        header = Panel(
            f"🎭 [bold bright_yellow]Demo Scanner[/bold bright_yellow] - "
            f"Interface: {self.interface} | "
            f"Devices: {len(self.demo_devices)} | "
            f"Packets: {self.stats.total_packets:,}",
            style="bright_yellow"
        )
        layout["header"].update(header)
        
        # Device table
        device_table = self._create_device_table()
        layout["devices"].update(Panel(device_table, title="🎭 Demo Devices", style="green"))
        
        # Statistics
        stats_panel = self._create_stats_panel()
        layout["stats"].update(stats_panel)
        
        # Footer
        footer = Panel(
            "[dim]Demo Plugin - Press Ctrl+C to stop[/dim]",
            style="dim"
        )
        layout["footer"].update(footer)
    
    def _create_device_table(self) -> Table:
        """Create demo device table."""
        table = Table(show_header=True, header_style="bold bright_yellow")
        table.add_column("Device ID", style="cyan")
        table.add_column("First Seen", style="green")
        table.add_column("Last Seen", style="green")
        table.add_column("Packets", style="magenta", justify="right")
        
        for device_id, device_info in list(self.demo_devices.items())[:10]:
            table.add_row(
                device_id,
                device_info["first_seen"].strftime("%H:%M:%S"),
                device_info["last_seen"].strftime("%H:%M:%S"),
                str(device_info["packet_count"])
            )
        
        return table
    
    def _create_stats_panel(self) -> Panel:
        """Create demo statistics panel."""
        duration = self.stats.session_duration_seconds
        rate = self.stats.packets_per_second
        
        stats_text = f"""📊 [bold]Demo Statistics[/bold]
        
🕐 Duration: {duration:.1f}s
📦 Packets: {self.stats.total_packets:,}
🎭 Demo Devices: {len(self.demo_devices)}
⚡ Rate: {rate:.1f} pkt/s
🎯 Target Rate: {self.packet_rate} pkt/s"""
        
        return Panel(stats_text, title="📈 Demo Stats", style="yellow")
    
    def handle_keyboard_input(self, key: str) -> None:
        """Handle keyboard input for demo plugin."""
        if key.lower() == 'd':
            # Create a new demo device
            device_id = f"demo_device_{len(self.demo_devices) + 1}"
            self.demo_devices[device_id] = {
                "first_seen": datetime.now(),
                "last_seen": datetime.now(),
                "packet_count": 1
            }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get demo plugin statistics."""
        return {
            "protocol": "Demo",
            "interface": self.interface,
            "devices": len(self.demo_devices),
            "packets": self.stats.total_packets,
            "valid_packets": self.stats.valid_packets,
            "error_rate": self.stats.error_rate,
            "packets_per_second": self.stats.packets_per_second,
            "target_rate": self.packet_rate,
            "output_files": {}
        }
'''

DEMO_INIT_CODE = '''"""
Demo plugin package.
"""

from .plugin import DemoPlugin

__all__ = ["DemoPlugin"]
'''


def create_demo_plugin():
    """Create a demo plugin to show the plugin system."""

    # Get the project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    plugins_dir = project_root / "src" / "plugins"

    # Create demo plugin directory
    demo_dir = plugins_dir / "demo"
    demo_dir.mkdir(exist_ok=True)

    # Write plugin files
    (demo_dir / "__init__.py").write_text(DEMO_INIT_CODE)
    (demo_dir / "plugin.py").write_text(DEMO_PLUGIN_CODE)

    print(f"✅ Created demo plugin at: {demo_dir}")
    print(f"📁 Plugin files:")
    print(f"   - {demo_dir / '__init__.py'}")
    print(f"   - {demo_dir / 'plugin.py'}")
    print()
    print(f"🎯 To test the demo plugin:")
    print(f"   python main.py plugins")
    print(f"   python main.py scan --protocol demo")
    print()
    print(f"🗑️  To remove the demo plugin:")
    print(f"   rm -rf {demo_dir}")


if __name__ == "__main__":
    create_demo_plugin()
