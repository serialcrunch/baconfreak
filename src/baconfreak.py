#!/usr/bin/env python3
"""
Bluetooth Low Energy packet analysis tool.

This module provides enhanced capabilities using Pydantic, Loguru, Rich, and other
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

from .company_identifiers import CompanyIdentifiers
from .config import config
from .device_detector import DeviceDetector
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
def pcap_writers(known_path: Path, unknown_path: Path, devices_path: Path):
    """
    Context manager for PCAP writers with proper resource cleanup.

    Args:
        known_path: Path for known devices PCAP file
        unknown_path: Path for unknown devices PCAP file
        devices_path: Path for specific device types PCAP file

    Yields:
        Tuple of (known_writer, unknown_writer, devices_writer)
    """
    known_writer = None
    unknown_writer = None
    devices_writer = None

    try:
        # Ensure output directory exists
        known_path.parent.mkdir(parents=True, exist_ok=True)

        known_writer = PcapWriter(str(known_path))
        unknown_writer = PcapWriter(str(unknown_path))
        devices_writer = PcapWriter(str(devices_path))

        yield known_writer, unknown_writer, devices_writer

    finally:
        if known_writer:
            known_writer.close()
        if unknown_writer:
            unknown_writer.close()
        if devices_writer:
            devices_writer.close()


class BluetoothScanner:
    """Bluetooth Low Energy scanner with Rich UI and structured logging."""

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
        self._exit_message = None  # Store exit message to display in TUI

        # Device tracking
        self.devices: Dict[str, BluetoothDevice] = {}
        self.stats = DeviceStats()
        
        # Generate session timestamp for PCAP file naming
        self.session_timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        
        # Store actual PCAP paths used (will be set in run method)
        self.actual_known_pcap_path: Optional[Path] = None
        self.actual_unknown_pcap_path: Optional[Path] = None
        self.actual_devices_pcap_path: Optional[Path] = None

        # Performance tracking
        self._last_stats_update = datetime.now()
        self._packet_buffer: list = []

        # TUI sorting state
        self.sort_mode = "last_seen"  # Default sort by last seen
        self.sort_ascending = False  # Default descending (most recent first)
        self.sort_modes = {
            "last_seen": ("Last Seen", lambda d: d.last_seen),
            "first_seen": ("First Seen", lambda d: d.first_seen), 
            "rssi": ("RSSI", lambda d: d.rssi),
            "total_time": ("Total Time", lambda d: (datetime.now() - d.first_seen).total_seconds()),
            "packets": ("Packets", lambda d: d.packet_count)
        }

        # Initialize components
        try:
            self.company_resolver = CompanyIdentifiers()
            self.device_detector = DeviceDetector(self.company_resolver)
        except Exception as e:
            logger.error(f"Failed to initialize components: {e}")
            raise BaconFreakError(f"Initialization failed: {e}")

        # Set up signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum: int, frame: Any):
        """Handle shutdown signals gracefully."""
        if not self._running:
            # Already shutting down, force exit
            self._exit_message = "🔥 [red]Force quitting...[/red]"
            logger.warning("Second signal received, forcing exit...")
            import sys
            sys.exit(0)
        
        # Show immediate feedback that Ctrl+C was detected
        self._exit_message = "🛑 [yellow]Exiting...[/yellow]"
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
    
    def _get_timestamped_pcap_path(self, base_filename: str) -> Path:
        """Generate a timestamped PCAP filename with Bacon prefix."""
        path = Path(base_filename)
        stem = path.stem
        suffix = path.suffix
        timestamped_filename = f"Bacon-{self.session_timestamp}-{stem}{suffix}"
        return path.parent / timestamped_filename

    def stop(self):
        """Stop the scanning process."""
        self.exit_event.set()
        self._running = False

    def _handle_keyboard_input(self, key: str) -> None:
        """Handle keyboard input for sorting and controls."""
        if key.lower() == 'r':  # Toggle RSSI sorting
            if self.sort_mode == "rssi":
                self.sort_ascending = not self.sort_ascending
            else:
                self.sort_mode = "rssi"
                self.sort_ascending = False  # Start with strongest signal first
        elif key.lower() == 'f':  # Toggle First Seen sorting
            if self.sort_mode == "first_seen":
                self.sort_ascending = not self.sort_ascending
            else:
                self.sort_mode = "first_seen"
                self.sort_ascending = False  # Start with most recent first
        elif key.lower() == 'l':  # Toggle Last Seen sorting
            if self.sort_mode == "last_seen":
                self.sort_ascending = not self.sort_ascending
            else:
                self.sort_mode = "last_seen"
                self.sort_ascending = False  # Start with most recent first
        elif key.lower() == 't':  # Toggle Total Time sorting
            if self.sort_mode == "total_time":
                self.sort_ascending = not self.sort_ascending
            else:
                self.sort_mode = "total_time"
                self.sort_ascending = False  # Start with longest time first
        elif key.lower() == 'p':  # Toggle Packets sorting
            if self.sort_mode == "packets":
                self.sort_ascending = not self.sort_ascending
            else:
                self.sort_mode = "packets"
                self.sort_ascending = False  # Start with most packets first

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
        # Header with sort info
        sort_name = self.sort_modes[self.sort_mode][0]
        sort_dir = "↑" if self.sort_ascending else "↓"
        
        header = Panel(
            f"🥓  [bold bright_blue]baconfreak Live Monitor[/bold bright_blue] - "
            f"Interface: HCI{self.scan_config.interface} | "
            f"Devices: {len(self.devices)} | "
            f"Packets: {self.stats.total_packets:,} | "
            f"Sort: [yellow]{sort_name} {sort_dir}[/yellow]",
            style="bright_blue",
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
        table = Table(show_header=True, header_style="bold bright_blue")
        table.add_column("Type", style="cyan", width=12)
        table.add_column("Address", style="white", width=17)
        table.add_column("RSSI", style="yellow", width=5, justify="right")
        table.add_column("Company", style="green", width=15)
        table.add_column("Pkts", style="magenta", width=4, justify="right")
        table.add_column("First", style="dim", width=8)
        table.add_column("Last", style="dim", width=8)
        table.add_column("Total", style="dim", width=8)

        # Sort devices based on current sort mode
        if self.devices:
            sort_key = self.sort_modes[self.sort_mode][1]
            recent_devices = sorted(
                self.devices.values(), 
                key=sort_key, 
                reverse=not self.sort_ascending
            )[:20]
        else:
            recent_devices = []

        for device in recent_devices:
            now = datetime.now()
            last_seen_delta = now - device.last_seen
            total_time_delta = now - device.first_seen
            
            # Format last seen
            last_seen_str = self._format_time_delta(last_seen_delta)
            
            # Format first seen (show actual time if recent, otherwise relative)
            if total_time_delta.total_seconds() < 3600:  # Less than 1 hour
                first_seen_str = device.first_seen.strftime("%H:%M:%S")
            else:
                first_seen_str = self._format_time_delta(total_time_delta) + " ago"
            
            # Format total time seen
            total_time_str = self._format_time_delta(total_time_delta)

            # Color RSSI based on signal strength
            rssi_style = "green" if device.rssi > -50 else "yellow" if device.rssi > -70 else "red"

            table.add_row(
                device.device_type.value,
                device.addr,
                f"[{rssi_style}]{device.rssi}[/{rssi_style}]",
                device.company_name or "Unknown",
                str(device.packet_count),
                first_seen_str,
                last_seen_str,
                total_time_str,
            )

        return table

    def _format_time_delta(self, delta) -> str:
        """Format a timedelta into a compact human-readable string."""
        total_seconds = int(delta.total_seconds())
        
        if total_seconds < 60:
            return f"{total_seconds}s"
        elif total_seconds < 3600:  # Less than 1 hour
            minutes = total_seconds // 60
            return f"{minutes}m"
        elif total_seconds < 86400:  # Less than 1 day
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            if minutes > 0:
                return f"{hours}h{minutes}m"
            else:
                return f"{hours}h"
        else:  # 1 day or more
            days = total_seconds // 86400
            hours = (total_seconds % 86400) // 3600
            if hours > 0:
                return f"{days}d{hours}h"
            else:
                return f"{days}d"

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
        """Create footer with keyboard shortcuts."""
        footer_text = (
            "[dim]Controls: [/dim]"
            "[bright_blue]R[/bright_blue]=[dim]RSSI[/dim] | "
            "[bright_blue]F[/bright_blue]=[dim]First Seen[/dim] | "
            "[bright_blue]L[/bright_blue]=[dim]Last Seen[/dim] | "
            "[bright_blue]T[/bright_blue]=[dim]Total Time[/dim] | "
            "[bright_blue]P[/bright_blue]=[dim]Packets[/dim]"
        )
        return Panel(footer_text, style="dim")

    def _packet_callback(self, packet, known_writer: PcapWriter, unknown_writer: PcapWriter, devices_writer: PcapWriter):
        """Process captured Bluetooth packets."""
        try:
            if not packet.haslayer(HCI_LE_Meta_Advertising_Reports):
                return

            # Extract all advertising reports from the packet
            reports = chain.from_iterable(
                p[HCI_LE_Meta_Advertising_Reports].reports for p in packet
            )

            for report in reports:
                self._process_advertising_report(report, packet, known_writer, unknown_writer, devices_writer)

        except Exception as e:
            self.logger.error_with_context(e, "Error processing packet")
            self.stats.total_packets += 1  # Count failed packets

    def _process_advertising_report(
        self, report, original_packet, known_writer: PcapWriter, unknown_writer: PcapWriter, devices_writer: PcapWriter
    ):
        """Process a single advertising report."""
        packet_info = None
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
            # Three-way classification: devices PCAP, known PCAP, or unknown PCAP
            device_type_str = device.device_type.value
            is_special_device = device_type_str in config.device_types_for_devices_pcap
            is_known_company = packet_info.company_id and self.device_detector.is_known_company(
                packet_info.company_id
            )
            
            if is_special_device:
                # Write to devices PCAP for configured device types
                devices_writer.write(original_packet)
                if device.company_name:
                    self.stats.known_companies.add(device.company_name)
            elif is_known_company:
                # Write to known PCAP for known companies
                known_writer.write(original_packet)
                if device.company_name:
                    self.stats.known_companies.add(device.company_name)
            else:
                # Write to unknown PCAP for everything else
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

            ans, unans = bt_socket.sr(scan_command, verbose=False)
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

        if not self.quiet and self.enable_rich and self.console:
            self.console.print(
                Panel.fit(
                    f"🥓  [bold bright_blue]Starting baconfreak[/bold bright_blue]\n\n"
                    f"Interface: [cyan]HCI{self.scan_config.interface}[/cyan]\n"
                    f"Output: [cyan]{config.output_dir_path}[/cyan]\n"
                    f"Min RSSI: [cyan]{self.scan_config.min_rssi} dBm[/cyan]",
                    style="bright_blue",
                )
            )

        try:
            # Initialize Bluetooth interface
            bt_socket = self._initialize_bluetooth_interface()
            self._running = True

            # Set up PCAP writers with timestamped filenames
            known_pcap_path = self._get_timestamped_pcap_path(config.known_pcap_path)
            unknown_pcap_path = self._get_timestamped_pcap_path(config.unknown_pcap_path)
            devices_pcap_path = self._get_timestamped_pcap_path(config.devices_pcap_path)
            
            # Store actual paths for summary display
            self.actual_known_pcap_path = known_pcap_path
            self.actual_unknown_pcap_path = unknown_pcap_path
            self.actual_devices_pcap_path = devices_pcap_path
            
            with pcap_writers(known_pcap_path, unknown_pcap_path, devices_pcap_path) as (
                known_writer,
                unknown_writer,
                devices_writer,
            ):

                def packet_handler(packet):
                    self._packet_callback(packet, known_writer, unknown_writer, devices_writer)

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

                        # Set up keyboard input using a separate thread that doesn't interfere with Rich
                        import queue
                        import sys
                        import termios
                        import tty
                        
                        # Create a queue to communicate between keyboard thread and main thread
                        key_queue = queue.Queue()
                        
                        def keyboard_listener():
                            """Listen for keyboard input in a separate thread."""
                            stdin_fd = sys.stdin.fileno()
                            old_settings = None
                            try:
                                # Save original terminal settings
                                old_settings = termios.tcgetattr(stdin_fd)
                                
                                # Set terminal to raw mode for single char input without echo
                                new_settings = termios.tcgetattr(stdin_fd)
                                new_settings[3] = new_settings[3] & ~(termios.ECHO | termios.ICANON)  # Disable echo and canonical mode
                                new_settings[6][termios.VMIN] = 1  # Read at least 1 character
                                new_settings[6][termios.VTIME] = 0  # No timeout
                                termios.tcsetattr(stdin_fd, termios.TCSADRAIN, new_settings)
                                
                                while self._running:
                                    try:
                                        # Use select to check if input is available (non-blocking check)
                                        import select
                                        ready, _, _ = select.select([sys.stdin], [], [], 0.1)  # 100ms timeout
                                        
                                        if ready and self._running:
                                            key = sys.stdin.read(1)
                                            if key:
                                                # Let signal handlers handle Ctrl+C (ASCII 3)
                                                # Only process regular keys here
                                                if ord(key) != 3:
                                                    key_queue.put(key)
                                                    
                                    except (KeyboardInterrupt, EOFError):
                                        self.stop()
                                        break
                                    except Exception:
                                        continue  # Continue on other errors
                                        
                            except Exception:
                                pass
                            finally:
                                # Always restore terminal settings
                                if old_settings is not None:
                                    try:
                                        termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_settings)
                                    except Exception:
                                        pass
                        
                        # Start keyboard listener thread
                        keyboard_thread = threading.Thread(target=keyboard_listener, daemon=True)
                        keyboard_thread.start()
                        
                        # Update display while scanning
                        while self._running and capture_thread.is_alive():
                            if self._exit_message:
                                # Replace device table with exit message
                                self._update_display_with_exit_message(layout)
                            else:
                                # Normal display update
                                self._update_display(layout)
                            
                            # Process any keyboard input from the queue (non-blocking)
                            try:
                                while True:
                                    key = key_queue.get_nowait()
                                    self._handle_keyboard_input(key)
                            except queue.Empty:
                                pass  # No keys in queue
                            
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

    def _update_display_with_exit_message(self, layout: Layout):
        """Update display with exit message replacing the device table."""
        # Update header and stats normally
        sort_name = self.sort_modes[self.sort_mode][0]
        sort_dir = "↑" if self.sort_ascending else "↓"
        
        header = Panel(
            f"🥓  [bold bright_blue]baconfreak Live Monitor[/bold bright_blue] - "
            f"Interface: HCI{self.scan_config.interface} | "
            f"Devices: {len(self.devices)} | "
            f"Packets: {self.stats.total_packets:,} | "
            f"Sort: [yellow]{sort_name} {sort_dir}[/yellow]",
            style="bright_blue",
        )
        layout["header"].update(header)
        
        # Create exit message panel to replace device table
        from rich.align import Align
        from rich.text import Text
        
        exit_panel = Panel(
            Align.center(
                Text.from_markup(self._exit_message, style="bold"),
                vertical="middle"
            ),
            title="⚠️  Exit Status",
            border_style="yellow" if "Exiting" in self._exit_message else "red",
            style="green"
        )
        
        # Replace the devices section with the exit message
        layout["devices"].update(exit_panel)
        
        # Update statistics normally
        stats_content = self._create_stats_panel()
        layout["stats"].update(stats_content)
        
        # Update footer normally
        footer = self._create_footer()
        layout["footer"].update(footer)

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
        if not self.console:
            return
            
        # Main summary panel
        summary_table = Table(show_header=True, header_style="bold bright_blue")
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
        
📤 Known devices: [cyan]{self.actual_known_pcap_path or config.known_pcap_path}[/cyan]
❓ Unknown devices: [cyan]{self.actual_unknown_pcap_path or config.unknown_pcap_path}[/cyan]
🎯 Special devices: [cyan]{self.actual_devices_pcap_path or config.devices_pcap_path}[/cyan]
📋 Log file: [cyan]{config.logs_dir_path / 'baconfreak.log'}[/cyan]"""

        self.console.print(Panel(files_text, title="💾 Files", style="bright_blue"))

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
            print(f"  Known devices: {self.actual_known_pcap_path or config.known_pcap_path}")
            print(f"  Unknown devices: {self.actual_unknown_pcap_path or config.unknown_pcap_path}")
            print(f"  Special devices: {self.actual_devices_pcap_path or config.devices_pcap_path}")


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
            logger.error_with_context(e, "Permission error")
            if hasattr(sys.stderr, "isatty") and sys.stderr.isatty():
                print("Error: Root privileges required. Try: sudo python baconfreak.py")
            sys.exit(1)

        except BaconFreakInterfaceError as e:
            logger.error_with_context(e, "Interface error")
            if hasattr(sys.stderr, "isatty") and sys.stderr.isatty():
                print("Error: Bluetooth interface not available. Try: sudo hciconfig hci1 up")
            sys.exit(1)

        except BaconFreakError as e:
            logger.error_with_context(e, "Application error")
            sys.exit(1)

        except Exception as e:
            logger.error_with_context(e, "Unexpected error")
            sys.exit(1)


if __name__ == "__main__":
    main()
