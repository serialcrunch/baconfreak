"""
Common UI utilities shared between plugins.
"""

from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..utils import format_rssi_with_quality, format_time_delta


class SortManager:
    """Manages sorting state and operations for plugin displays."""

    def __init__(self, initial_mode: str = "last_seen", initial_ascending: bool = False):
        self.sort_mode = initial_mode
        self.sort_ascending = initial_ascending
        self.sort_modes: Dict[str, Tuple[str, Callable]] = {}

    def register_sort_mode(self, key: str, display_name: str, sort_func: Callable):
        """Register a new sort mode."""
        self.sort_modes[key] = (display_name, sort_func)

    def handle_sort_key(self, key: str) -> bool:
        """Handle keyboard input for sorting. Returns True if sort changed."""
        if key.lower() in self.sort_modes:
            if self.sort_mode == key.lower():
                self.sort_ascending = not self.sort_ascending
            else:
                self.sort_mode = key.lower()
                self.sort_ascending = False
            return True
        return False

    def get_sort_display(self) -> str:
        """Get current sort mode display string."""
        if self.sort_mode not in self.sort_modes:
            return "Unknown"
        sort_name = self.sort_modes[self.sort_mode][0]
        sort_dir = "↑" if self.sort_ascending else "↓"
        return f"{sort_name} {sort_dir}"

    def sort_items(self, items: List[Any], limit: Optional[int] = None) -> List[Any]:
        """Sort items using current sort configuration."""
        if not items or self.sort_mode not in self.sort_modes:
            return items[:limit] if limit else items

        sort_func = self.sort_modes[self.sort_mode][1]
        sorted_items = sorted(items, key=sort_func, reverse=not self.sort_ascending)
        return sorted_items[:limit] if limit else sorted_items


class DeviceTableFormatter:
    """Formats device tables with common patterns."""

    @staticmethod
    def format_time_columns(device: Any) -> Tuple[str, str, str]:
        """Format time-related columns (first_seen, last_seen, total_time)."""
        now = datetime.now()
        last_seen_delta = now - device.last_seen
        total_time_delta = now - device.first_seen

        # Format times
        last_seen_str = format_time_delta(last_seen_delta)
        if total_time_delta.total_seconds() < 3600:
            first_seen_str = device.first_seen.strftime("%H:%M:%S")
        else:
            first_seen_str = format_time_delta(total_time_delta) + " ago"
        total_time_str = format_time_delta(total_time_delta)

        return first_seen_str, last_seen_str, total_time_str

    @staticmethod
    def format_rssi_column(rssi: int, threshold: int = -100) -> str:
        """Format RSSI column with quality coloring."""
        if rssi <= threshold:
            return "-"
        rssi_value, rssi_style = format_rssi_with_quality(rssi)
        return f"[{rssi_style}]{rssi_value}[/{rssi_style}]"


class ErrorDisplayManager:
    """Manages structured error display patterns."""

    @staticmethod
    def create_interface_error_panel(
        protocol: str, interface: str, icon: str, solutions: List[Tuple[str, str]]
    ) -> Panel:
        """Create a standardized interface error panel."""
        error_text = Text()
        error_text.append(f"❌ {protocol} Interface Error\n\n", style="bold red")
        error_text.append(f"{protocol} interface {interface} is not available.\n\n", style="white")
        error_text.append("Solutions:\n", style="yellow")

        for i, (description, command) in enumerate(solutions, 1):
            error_text.append(f"{i}. {description}: ", style="white")
            error_text.append(f"{command}\n", style="cyan")

        return Panel(error_text, title=f"{icon} {protocol} Plugin", border_style="red")


class StatsFormatter:
    """Common statistics formatting utilities."""

    @staticmethod
    def format_basic_stats(stats: Any, device_count: int, protocol: str) -> str:
        """Format basic statistics common to all plugins."""
        duration = stats.session_duration_seconds
        rate = stats.packets_per_second

        return f"""📊 [bold]{protocol} Statistics[/bold]
        
🕐 Duration: {duration:.1f}s
📦 Packets: {stats.total_packets:,}
📱 Devices: {device_count}
⚡ Rate: {rate:.1f} pkt/s
❌ Error Rate: {stats.error_rate:.2%}"""

    @staticmethod
    def create_stats_panel(content: str, title: str = "📈 Stats", style: str = "yellow") -> Panel:
        """Create a standardized statistics panel."""
        return Panel(content, title=title, style=style)


class TableColumnConfig:
    """Centralized table column configuration."""

    # Standard column widths
    COLUMNS = {
        "type": {"style": "cyan", "width": 12},
        "address": {"style": "white", "width": 17},
        "ssid": {"style": "white", "width": 18},
        "bssid": {"style": "white", "width": 17},
        "rssi": {"style": "yellow", "width": 5, "justify": "right"},
        "company": {"style": "green", "width": 15},
        "channel": {"style": "blue", "width": 3, "justify": "center"},
        "packets": {"style": "magenta", "width": 4, "justify": "right"},
        "first_seen": {"style": "dim", "width": 8},
        "last_seen": {"style": "dim", "width": 8},
        "total_time": {"style": "dim", "width": 8},
    }

    @classmethod
    def add_standard_column(
        cls, table: Table, column_name: str, display_name: Optional[str] = None
    ):
        """Add a standard column to a table."""
        if column_name not in cls.COLUMNS:
            raise ValueError(f"Unknown column: {column_name}")

        config = cls.COLUMNS[column_name]
        table.add_column(
            display_name or column_name.title(),
            style=config["style"],
            width=config.get("width"),
            justify=config.get("justify", "left"),  # type: ignore
        )


class FooterBuilder:
    """Builds standardized footer panels for plugins."""

    @staticmethod
    def create_sort_footer(sort_keys: Dict[str, str], style: str = "dim") -> Panel:
        """Create a sort key footer panel."""
        footer_parts = []
        for key, description in sort_keys.items():
            footer_parts.append(
                f"[bright_blue]{key.upper()}[/bright_blue]=[dim]{description}[/dim]"
            )

        footer_text = "[dim]Sort: [/dim]" + " | ".join(footer_parts)
        return Panel(footer_text, style=style)
