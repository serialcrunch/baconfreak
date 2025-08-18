#!/usr/bin/env python3
"""
Modern Bluetooth Low Energy packet analysis tool.

This module provides a modernized version using Pydantic, Loguru, Rich, and other
industry-standard packages for better performance, maintainability, and user experience.
"""

import signal
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from itertools import chain
from pathlib import Path
from typing import Any, Dict, Optional, Set

from loguru import logger
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table
from scapy.layers.bluetooth import (
    BluetoothHCISocket,
    HCI_Cmd_LE_Set_Scan_Enable,
    HCI_Command_Hdr,
    HCI_Hdr,
    HCI_LE_Meta_Advertising_Reports,
)
from scapy.utils import PcapWriter

from .company_identifiers import ModernCompanyIdentifiers
from .config import config
from .device_detector import ModernDeviceDetector
from .logger import BaconFreakLogger, setup_logging
from .models import BluetoothDevice, DeviceStats, DeviceType, PacketInfo, ScanConfiguration


class BaconFreakError(Exception):
    """Base exception for baconfreak errors."""

    pass


class BaconFreakPermissionError(BaconFreakError):
    """Raised when insufficient permissions for Bluetooth operations."""

    pass


class BaconFreakInterfaceError(BaconFreakError):
    """Raised when Bluetooth interface is not available."""

    pass


@contextmanager
def pcap_writers(known_path: Path, unknown_path: Path):
    """
    Context manager for PCAP writers with proper resource cleanup.

    Args:
        known_path: Path for known devices PCAP file
        unknown_path: Path for unknown devices PCAP file

    Yields:
        Tuple of (known_writer, unknown_writer)
    """
    known_writer = None
    unknown_writer = None

    try:
        # Ensure output directory exists
        known_path.parent.mkdir(parents=True, exist_ok=True)

        known_writer = PcapWriter(str(known_path))
        unknown_writer = PcapWriter(str(unknown_path))

        yield known_writer, unknown_writer

    finally:
        if known_writer:
            known_writer.close()
        if unknown_writer:
            unknown_writer.close()


class BluetoothScanner:
    """Modern Bluetooth Low Energy scanner with Rich UI and structured logging."""

    def __init__(
        self,
        interface: Optional[int] = None,
        scan_config: Optional[ScanConfiguration] = None,
        enable_rich: bool = True,
        quiet: bool = False,
    ):
        """
        Initialize the modern Bluetooth scanner.

        Args:
            interface: Bluetooth HCI interface number
            scan_config: Scan configuration (uses default if None)
            enable_rich: Enable Rich UI features
            quiet: Quiet mode with minimal output
        """
        self.scan_config = scan_config or config.scan_config
        if interface is not None:
            self.scan_config.interface = interface

        self.enable_rich = enable_rich and not quiet
        self.quiet = quiet

        # Setup logging (will be configured by main app)
        self.logger = BaconFreakLogger("scanner")

        # Rich console for beautiful output
        self.console = Console() if self.enable_rich else None

        # Threading control
        self.exit_event = threading.Event()
        self._running = False

        # Device tracking
        self.devices: Dict[str, BluetoothDevice] = {}
        self.stats = DeviceStats()

        # Performance tracking
        self._last_stats_update = datetime.now()
        self._packet_buffer: list = []

        # Initialize components
        try:
            self.company_resolver = ModernCompanyIdentifiers()
            self.device_detector = ModernDeviceDetector(self.company_resolver)
        except Exception as e:
            logger.error(f"Failed to initialize components: {e}")
            raise BaconFreakError(f"Initialization failed: {e}")

        # Set up signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum: int, frame: Any):
        """Handle shutdown signals gracefully."""
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop()

    def stop(self):
        """Stop the scanning process."""
        self.exit_event.set()
        self._running = False

    def _create_live_display(self) -> Layout:
        """Create Rich live display layout."""
        layout = Layout()

        layout.split_column(
            Layout(name="header", size=3), Layout(name="main"), Layout(name="footer", size=8)
        )

        layout["main"].split_row(Layout(name="devices", ratio=2), Layout(name="stats", ratio=1))

        return layout

    def _update_display(self, layout: Layout):
        """Update the live display with current data."""
        # Header
        header = Panel(
            f"🛰️  [bold blue]baconfreak Live Monitor[/bold blue] - "
            f"Interface: HCI{self.scan_config.interface} | "
            f"Devices: {len(self.devices)} | "
            f"Packets: {self.stats.total_packets:,}",
            style="blue",
        )
        layout["header"].update(header)

        # Device table
        device_table = self._create_device_table()
        layout["devices"].update(Panel(device_table, title="🔍 Detected Devices", style="green"))

        # Statistics
        stats_content = self._create_stats_panel()
        layout["stats"].update(stats_content)

        # Footer with recent activity
        footer = self._create_footer()
        layout["footer"].update(footer)

    def _create_device_table(self) -> Table:
        """Create table of detected devices."""
        table = Table(show_header=True, header_style="bold blue")
        table.add_column("Type", style="cyan")
        table.add_column("Address", style="white")
        table.add_column("RSSI", style="yellow")
        table.add_column("Company", style="green")
        table.add_column("Packets", style="magenta")
        table.add_column("Last Seen", style="dim")

        # Show most recent devices (limit for performance)
        recent_devices = sorted(self.devices.values(), key=lambda d: d.last_seen, reverse=True)[:20]

        for device in recent_devices:
            age = datetime.now() - device.last_seen
            age_str = f"{age.seconds}s ago" if age.seconds < 60 else f"{age.seconds//60}m ago"

            # Color RSSI based on signal strength
            rssi_style = "green" if device.rssi > -50 else "yellow" if device.rssi > -70 else "red"

            table.add_row(
                device.device_type.value,
                device.addr,
                f"[{rssi_style}]{device.rssi}[/{rssi_style}]",
                device.company_name or "Unknown",
                str(device.packet_count),
                age_str,
            )

        return table

    def _create_stats_panel(self) -> Panel:
        """Create statistics panel."""
        duration = self.stats.session_duration_seconds
        rate = self.stats.packets_per_second

        stats_text = f"""📊 [bold]Session Statistics[/bold]
        
🕐 Duration: {duration:.1f}s
📦 Packets: {self.stats.total_packets:,}
📱 Devices: {len(self.devices)}
⚡ Rate: {rate:.1f} pkt/s
❌ Error Rate: {self.stats.error_rate:.2%}

🏢 [bold]Companies[/bold]
✅ Known: {len(self.stats.known_companies)}
❓ Unknown: {len(self.stats.unknown_company_ids)}

🏷️  [bold]Device Types[/bold]"""

        for device_type, count in self.stats.devices_by_type.items():
            stats_text += f"\n{device_type.value}: {count}"

        return Panel(stats_text, title="📈 Statistics", style="yellow")

    def _create_footer(self) -> Panel:
        """Create footer with recent activity."""
        # Show recent log messages or activity
        footer_text = "[dim]Press Ctrl+C to stop scanning...[/dim]"
        return Panel(footer_text, style="dim")

    def _packet_callback(self, packet, known_writer: PcapWriter, unknown_writer: PcapWriter):
        """Process captured Bluetooth packets."""
        try:
            if not packet.haslayer(HCI_LE_Meta_Advertising_Reports):
                return

            # Extract all advertising reports from the packet
            reports = chain.from_iterable(
                p[HCI_LE_Meta_Advertising_Reports].reports for p in packet
            )

            for report in reports:
                self._process_advertising_report(report, packet, known_writer, unknown_writer)

        except Exception as e:
            self.logger.error_with_context(e, "Error processing packet")
            self.stats.total_packets += 1  # Count failed packets

    def _process_advertising_report(
        self, report, original_packet, known_writer: PcapWriter, unknown_writer: PcapWriter
    ):
        """Process a single advertising report."""
        try:
            # Extract packet information
            packet_info = self.device_detector.extract_packet_info(report)
            if not packet_info:
                return

            # Apply RSSI filter
            if packet_info.rssi < self.scan_config.min_rssi:
                return

            self.stats.total_packets += 1
            self.stats.valid_packets += 1

            # Check if this is a new device or update existing
            device = self._get_or_create_device(packet_info)

            # Determine which PCAP file to write to
            if packet_info.company_id and self.device_detector.is_known_company(
                packet_info.company_id
            ):
                known_writer.write(original_packet)
                if device.company_name:
                    self.stats.known_companies.add(device.company_name)
            else:
                unknown_writer.write(original_packet)
                if packet_info.company_id:
                    self.stats.unknown_company_ids.add(packet_info.company_id)

            # Update performance statistics
            self._update_performance_stats()

        except Exception as e:
            self.logger.error_with_context(
                e, f"Error processing report from {packet_info.addr if packet_info else 'unknown'}"
            )

    def _get_or_create_device(self, packet_info: PacketInfo) -> BluetoothDevice:
        """Get existing device or create new one."""
        addr = packet_info.addr

        if addr in self.devices:
            # Update existing device
            device = self.devices[addr]
            device.update_seen(packet_info.rssi, packet_info.data, packet_info.device_name)
        else:
            # Create new device
            device = self.device_detector.create_device(packet_info)
            self.devices[addr] = device
            self.stats.add_device(device)

            # Log device detection
            self.logger.device_detected(
                device.device_type.value, device.addr, device.rssi, device.data, device.company_name
            )

        return device

    def _update_performance_stats(self):
        """Update performance statistics."""
        now = datetime.now()
        if (now - self._last_stats_update).seconds >= config.get(
            "performance.statistics_interval", 10
        ):
            self.stats.update_packets_per_second()
            self._last_stats_update = now

            # Log performance metrics
            self.logger.performance_metric(
                "packets_per_second",
                self.stats.packets_per_second,
                "pkt/s",
                total_packets=self.stats.total_packets,
                devices=len(self.devices),
            )

    def _stop_filter(self, packet) -> bool:
        """Filter function to stop packet capture when exit event is set."""
        return self.exit_event.is_set()

    def _initialize_bluetooth_interface(self) -> BluetoothHCISocket:
        """Initialize Bluetooth HCI interface for scanning."""
        try:
            bt_socket = BluetoothHCISocket(self.scan_config.interface)

            # Enable scanning
            scan_command = (
                HCI_Hdr()
                / HCI_Command_Hdr()
                / HCI_Cmd_LE_Set_Scan_Enable(
                    enable=True, filter_dups=self.scan_config.filter_duplicates
                )
            )

            ans, unans = bt_socket.sr(scan_command)
            if not ans:
                raise BaconFreakInterfaceError(
                    f"Failed to enable scanning on hci{self.scan_config.interface}"
                )

            response = ans[0][1]
            logger.debug(f"Scan enable response: {response.summary()}")

            return bt_socket

        except PermissionError:
            raise BaconFreakPermissionError(
                f"Permission denied accessing hci{self.scan_config.interface}. "
                "Root privileges required for Bluetooth operations."
            )
        except Exception as e:
            raise BaconFreakInterfaceError(
                f"Failed to initialize Bluetooth interface hci{self.scan_config.interface}: {e}"
            )

    def run(self):
        """Start the Bluetooth scanning process with Rich UI."""
        # Ensure directories exist
        config.ensure_directories()

        # Show startup information
        startup_config = {
            "interface": self.scan_config.interface,
            "timeout": self.scan_config.scan_timeout,
            "min_rssi": self.scan_config.min_rssi,
            "filter_duplicates": self.scan_config.filter_duplicates,
        }

        self.logger.startup_info(self.scan_config.interface, config.output_dir_path, startup_config)

        if not self.quiet and self.enable_rich:
            self.console.print(
                Panel.fit(
                    f"🛰️  [bold blue]Starting baconfreak[/bold blue]\n\n"
                    f"Interface: [cyan]HCI{self.scan_config.interface}[/cyan]\n"
                    f"Output: [cyan]{config.output_dir_path}[/cyan]\n"
                    f"Min RSSI: [cyan]{self.scan_config.min_rssi} dBm[/cyan]",
                    style="blue",
                )
            )

        try:
            # Initialize Bluetooth interface
            bt_socket = self._initialize_bluetooth_interface()
            self._running = True

            # Set up PCAP writers
            with pcap_writers(config.known_pcap_path, config.unknown_pcap_path) as (
                known_writer,
                unknown_writer,
            ):

                def packet_handler(packet):
                    self._packet_callback(packet, known_writer, unknown_writer)

                if not self.quiet and self.enable_rich:
                    # Run with Rich live display
                    layout = self._create_live_display()

                    with Live(layout, refresh_per_second=2, console=self.console) as live:
                        # Start packet capture in separate thread
                        def capture_packets():
                            bt_socket.sniff(
                                prn=packet_handler,
                                store=0,
                                stop_filter=self._stop_filter,
                                timeout=(
                                    self.scan_config.scan_timeout
                                    if self.scan_config.scan_timeout > 0
                                    else None
                                ),
                            )

                        capture_thread = threading.Thread(target=capture_packets)
                        capture_thread.daemon = True
                        capture_thread.start()

                        # Update display while scanning
                        while self._running and capture_thread.is_alive():
                            self._update_display(layout)
                            time.sleep(0.5)
                else:
                    # Simple mode without Rich UI
                    if not self.quiet:
                        print("Starting packet capture... (Press Ctrl+C to stop)")

                    bt_socket.sniff(
                        prn=packet_handler,
                        store=0,
                        stop_filter=self._stop_filter,
                        timeout=(
                            self.scan_config.scan_timeout
                            if self.scan_config.scan_timeout > 0
                            else None
                        ),
                    )

        except BaconFreakError:
            raise
        except KeyboardInterrupt:
            logger.info("Scan interrupted by user")
        except Exception as e:
            self.logger.error_with_context(e, "Unexpected error during scanning")
            raise BaconFreakError(f"Scanning failed: {e}")

        finally:
            self.stats.end_time = datetime.now()
            self._print_summary()
            if hasattr(self, "company_resolver"):
                self.company_resolver.close()

    def _print_summary(self):
        """Print scanning session summary."""
        duration = self.stats.session_duration_seconds

        if not self.quiet:
            if self.enable_rich and self.console:
                self._print_rich_summary(duration)
            else:
                self._print_simple_summary(duration)

        # Log summary
        self.logger.session_stats(
            devices=len(self.devices),
            packets=self.stats.total_packets,
            duration=duration,
            known_companies=len(self.stats.known_companies),
            unknown_companies=len(self.stats.unknown_company_ids),
        )

    def _print_rich_summary(self, duration: float):
        """Print Rich-formatted summary."""
        # Main summary panel
        summary_table = Table(show_header=True, header_style="bold blue")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="green")

        summary_table.add_row("Duration", f"{duration:.1f} seconds")
        summary_table.add_row("Total Packets", f"{self.stats.total_packets:,}")
        summary_table.add_row("Valid Packets", f"{self.stats.valid_packets:,}")
        summary_table.add_row("Unique Devices", f"{len(self.devices)}")
        summary_table.add_row("Packets/Second", f"{self.stats.packets_per_second:.1f}")
        summary_table.add_row("Error Rate", f"{self.stats.error_rate:.2%}")

        self.console.print(Panel(summary_table, title="📊 Session Summary", style="green"))

        # Device types breakdown
        if self.stats.devices_by_type:
            device_table = Table(show_header=True, header_style="bold yellow")
            device_table.add_column("Device Type", style="cyan")
            device_table.add_column("Count", style="yellow")

            for device_type, count in sorted(self.stats.devices_by_type.items()):
                device_table.add_row(device_type.value, str(count))

            self.console.print(Panel(device_table, title="🏷️  Device Types", style="yellow"))

        # Output files
        files_text = f"""📁 [bold]Output Files:[/bold]
        
📤 Known devices: [cyan]{config.known_pcap_path}[/cyan]
❓ Unknown devices: [cyan]{config.unknown_pcap_path}[/cyan]
📋 Log file: [cyan]{config.logs_dir_path / 'baconfreak.log'}[/cyan]"""

        self.console.print(Panel(files_text, title="💾 Files", style="blue"))

    def _print_simple_summary(self, duration: float):
        """Print simple text summary."""
        # Only print to console if not in quiet mode and TUI is disabled
        if not self.quiet and not self.enable_rich:
            print("\n" + "=" * 60)
            print("SCANNING SESSION SUMMARY")
            print("=" * 60)
            print(f"Duration: {duration:.1f} seconds")
            print(f"Total packets: {self.stats.total_packets:,}")
            print(f"Valid packets: {self.stats.valid_packets:,}")
            print(f"Unique devices: {len(self.devices)}")
            print(f"Packets/second: {self.stats.packets_per_second:.1f}")
            print(f"Error rate: {self.stats.error_rate:.2%}")

            if self.stats.devices_by_type:
                print("\nDevice Types:")
                for device_type, count in sorted(self.stats.devices_by_type.items()):
                    print(f"  {device_type.value}: {count}")

            print(f"\nOutput Files:")
            print(f"  Known devices: {config.known_pcap_path}")
            print(f"  Unknown devices: {config.unknown_pcap_path}")


def main():
    """Main entry point for the modern baconfreak application."""
    # Use CLI if available, otherwise fall back to direct execution
    try:
        from ..main import app

        app()
    except ImportError:
        # Fallback to direct execution
        logger = setup_logging()

        try:
            scanner = BluetoothScanner()
            scanner.run()

        except BaconFreakPermissionError as e:
            logger.error(f"Permission error: {e}")
            if hasattr(sys.stderr, "isatty") and sys.stderr.isatty():
                print("Error: Root privileges required. Try: sudo python baconfreak.py")
            sys.exit(1)

        except BaconFreakInterfaceError as e:
            logger.error(f"Interface error: {e}")
            if hasattr(sys.stderr, "isatty") and sys.stderr.isatty():
                print("Error: Bluetooth interface not available. Try: sudo hciconfig hci1 up")
            sys.exit(1)

        except BaconFreakError as e:
            logger.error(f"Application error: {e}")
            sys.exit(1)

        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
