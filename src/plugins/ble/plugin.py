"""
Bluetooth Low Energy (BLE) capture plugin.
"""

import signal
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from itertools import chain
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from scapy.layers.bluetooth import (
    BluetoothHCISocket,
    HCI_Cmd_LE_Set_Scan_Enable,
    HCI_Command_Hdr,
    HCI_Hdr,
    HCI_LE_Meta_Advertising_Reports,
)
from scapy.utils import PcapWriter

from ...company_identifiers import CompanyIdentifiers
from ...device_detector import DeviceDetector
from ...logger import BaconFreakLogger
from ...models import BluetoothDevice, DeviceStats, DeviceType, PacketInfo
from ...utils import format_time_delta, format_rssi_with_quality
from ..base import CapturePlugin, PluginError, PluginInfo, PluginRequirementError


class BLEPlugin(CapturePlugin):
    """Bluetooth Low Energy capture plugin."""
    
    def __init__(self, config: Dict[str, Any], console: Optional[Console] = None):
        super().__init__(config, console)
        
        # BLE-specific configuration
        interface_raw = config.get("interface", "hci1")
        # Handle legacy integer interface format for backward compatibility
        if isinstance(interface_raw, int):
            self.interface = f"hci{interface_raw}"
        else:
            self.interface = interface_raw
        self.scan_timeout = config.get("scan_timeout", 0)
        self.filter_duplicates = config.get("filter_duplicates", False)
        self.min_rssi = config.get("min_rssi", -100)
        self.adapter_name = config.get("adapter_name", "Built-in Bluetooth")
        
        # BLE-specific components
        self.company_resolver: Optional[CompanyIdentifiers] = None
        self.device_detector: Optional[DeviceDetector] = None
        self.bt_socket: Optional[BluetoothHCISocket] = None
        self.logger = BaconFreakLogger("ble_plugin")
        
        # UI state for sorting
        self.sort_mode = "last_seen"
        self.sort_ascending = False
        self.sort_modes = {
            "last_seen": ("Last Seen", lambda d: d.last_seen),
            "first_seen": ("First Seen", lambda d: d.first_seen), 
            "rssi": ("RSSI", lambda d: d.rssi),
            "total_time": ("Total Time", lambda d: (datetime.now() - d.first_seen).total_seconds()),
            "packets": ("Packets", lambda d: d.packet_count)
        }
        
        # PCAP writers
        self._pcap_writers: Optional[tuple] = None
        self._output_files: Dict[str, Path] = {}
    
    @property
    def info(self) -> PluginInfo:
        """Return BLE plugin information."""
        return PluginInfo(
            name="BLE Scanner",
            version="1.0.0", 
            description="Bluetooth Low Energy packet capture and device detection",
            protocol="ble",
            requires_root=True,
            supported_platforms=["linux"],
            config_schema={
                "enabled": {"type": "boolean", "default": True, "description": "Enable/disable plugin"},
                "interface": {"type": "string", "default": "hci1", "description": "HCI interface (e.g., hci0, hci1)"},
                "adapter_name": {"type": "string", "default": "Built-in Bluetooth", "description": "Bluetooth adapter name"},
                "scan_timeout": {"type": "integer", "default": 0, "description": "Scan timeout (0=infinite)"},
                "filter_duplicates": {"type": "boolean", "default": False, "description": "Filter duplicate packets"},
                "min_rssi": {"type": "integer", "default": -100, "description": "Minimum RSSI threshold"}
            }
        )
    
    def validate_config(self) -> tuple[bool, List[str]]:
        """Validate BLE plugin configuration."""
        errors = []
        
        # Validate interface format and existence
        if not isinstance(self.interface, str) or not self.interface:
            errors.append("interface must be a non-empty string")
        else:
            # Check if interface exists and is a valid HCI interface
            if not self._is_valid_hci_interface(self.interface):
                errors.append(f"interface '{self.interface}' is not a valid HCI interface")
        
        if not isinstance(self.scan_timeout, int) or self.scan_timeout < 0:
            errors.append("scan_timeout must be a non-negative integer")
        
        if not isinstance(self.min_rssi, int) or self.min_rssi < -127 or self.min_rssi > 20:
            errors.append("min_rssi must be between -127 and 20")
        
        return len(errors) == 0, errors
    
    def check_requirements(self) -> tuple[bool, List[str]]:
        """Check BLE plugin requirements."""
        errors = []
        
        # Check root privileges
        import os
        if os.geteuid() != 0:
            errors.append("Root privileges required for Bluetooth operations")
        
        # Check Scapy Bluetooth support
        try:
            from scapy.layers.bluetooth import BluetoothHCISocket
        except ImportError:
            errors.append("Scapy Bluetooth support not available")
        
        # Check HCI interface availability
        if not self._test_interface(self.interface):
            self._exit_with_interface_error()
        
        return len(errors) == 0, errors
    
    def _is_valid_hci_interface(self, interface_name: str) -> bool:
        """Check if interface is a valid HCI interface using hciconfig command."""
        import os
        try:
            # Check if interface exists in hciconfig output
            result = os.popen(f"hciconfig {interface_name} 2>/dev/null").read()
            if result and interface_name in result and "Type:" in result:
                return True
            
            # Alternative: Check if it appears in hciconfig list
            hci_list = os.popen("hciconfig 2>/dev/null").read()
            return f"{interface_name}:" in hci_list
        except Exception:
            return False
    
    def _test_interface(self, interface_name: str) -> bool:
        """Test if an HCI interface is available and working."""
        try:
            # First check if it's a valid HCI interface
            if not self._is_valid_hci_interface(interface_name):
                return False
            
            # Extract interface number from string (e.g., "hci1" -> 1)
            interface_num = int(interface_name[3:])
            test_socket = BluetoothHCISocket(interface_num)
            test_socket.close()
            return True
        except (PermissionError, ValueError, Exception):
            return False
    
    def _exit_with_interface_error(self) -> None:
        """Print error message and exit when interface is not available."""
        from rich.console import Console
        from rich.panel import Panel
        from rich.text import Text
        import sys
        
        console = Console()
        
        error_text = Text()
        error_text.append("❌ BLE Interface Error\n\n", style="bold red")
        error_text.append(f"Interface {self.interface} is not available.\n\n", style="white")
        error_text.append("Solutions:\n", style="yellow")
        error_text.append("1. Check available HCI interfaces: ", style="white")
        error_text.append("hciconfig\n", style="cyan")
        error_text.append("2. Check detailed interface status: ", style="white")
        error_text.append("hciconfig -a\n", style="cyan")
        error_text.append("3. Enable the Bluetooth interface: ", style="white")
        error_text.append(f"sudo hciconfig {self.interface} up\n", style="cyan")
        error_text.append("4. Check for Bluetooth hardware: ", style="white")
        error_text.append("lsusb | grep -i bluetooth\n", style="cyan")
        
        console.print(Panel(error_text, title=f"🔵 BLE Plugin - {self.adapter_name}", border_style="red"))
        sys.exit(1)
    
    def get_default_output_files(self, output_dir: Path) -> Dict[str, Path]:
        """Get default BLE output file paths."""
        return {
            "known_devices": output_dir / self.get_timestamped_filename("ble-known.pcap"),
            "unknown_devices": output_dir / self.get_timestamped_filename("ble-unknown.pcap"), 
            "special_devices": output_dir / self.get_timestamped_filename("ble-devices.pcap")
        }
    
    def initialize_capture(self) -> None:
        """Initialize BLE capture components."""
        try:
            # Initialize company resolver and device detector
            self.company_resolver = CompanyIdentifiers()
            self.device_detector = DeviceDetector(self.company_resolver)
            
            # Initialize Bluetooth socket
            interface_num = int(self.interface[3:])  # Extract number from "hci1" -> 1
            self.bt_socket = BluetoothHCISocket(interface_num)
            
            # Enable BLE scanning
            scan_command = (
                HCI_Hdr()
                / HCI_Command_Hdr()
                / HCI_Cmd_LE_Set_Scan_Enable(
                    enable=True, filter_dups=self.filter_duplicates
                )
            )
            
            ans, unans = self.bt_socket.sr(scan_command, verbose=False)
            if not ans:
                raise PluginError(f"Failed to enable scanning on {self.interface}")
            
            logger.info(f"BLE plugin initialized on {self.interface}")
            
        except PermissionError:
            raise PluginRequirementError(
                f"Permission denied accessing {self.interface}. Root privileges required."
            )
        except Exception as e:
            raise PluginError(f"Failed to initialize BLE capture: {e}")
    
    @contextmanager
    def _pcap_writers_context(self, output_files: Dict[str, Path]):
        """Context manager for PCAP writers."""
        writers = {}
        try:
            # Ensure output directory exists
            for file_path in output_files.values():
                file_path.parent.mkdir(parents=True, exist_ok=True)
            
            writers["known"] = PcapWriter(str(output_files["known_devices"]))
            writers["unknown"] = PcapWriter(str(output_files["unknown_devices"]))
            writers["special"] = PcapWriter(str(output_files["special_devices"]))
            
            self._output_files = output_files
            yield writers
            
        finally:
            for writer in writers.values():
                if writer:
                    writer.close()
    
    def start_capture(self, packet_callback, stop_event) -> None:
        """Start BLE packet capture."""
        if not self.bt_socket:
            raise PluginError("Plugin not initialized. Call initialize_capture() first.")
        
        self._running = True
        
        # Set up output files
        from ...config import config
        output_files = self.get_default_output_files(config.output_dir_path)
        
        def packet_handler(packet):
            if stop_event.is_set():
                return
            
            device_info = self.process_packet(packet)
            if device_info:
                packet_callback(device_info, packet)
        
        try:
            with self._pcap_writers_context(output_files) as writers:
                self._pcap_writers = (writers["known"], writers["unknown"], writers["special"])
                
                # Start packet capture with responsive timeout
                # Use shorter timeouts to make sniff more responsive to stop signals
                sniff_timeout = min(5.0, self.scan_timeout) if self.scan_timeout > 0 else 5.0
                end_time = time.time() + self.scan_timeout if self.scan_timeout > 0 else None
                
                while self._running and not stop_event.is_set():
                    if end_time and time.time() >= end_time:
                        break
                    
                    try:
                        self.bt_socket.sniff(
                            prn=lambda pkt: self._handle_packet(pkt, writers),
                            store=0,
                            stop_filter=lambda x: stop_event.is_set() or not self._running,
                            timeout=sniff_timeout
                        )
                    except (OSError, BrokenPipeError, ConnectionResetError) as e:
                        # Socket closed during operation - expected during shutdown
                        logger.debug(f"Socket closed during sniff: {e}")
                        break
                    except KeyboardInterrupt:
                        # Let KeyboardInterrupt propagate to signal handlers
                        raise
                    except Exception as e:
                        if "Interrupted system call" in str(e) or stop_event.is_set():
                            break
                        else:
                            raise
        except KeyboardInterrupt:
            # Let KeyboardInterrupt propagate to signal handlers
            logger.debug("KeyboardInterrupt in BLE capture, propagating...")
            raise
        except Exception as e:
            self.logger.error_with_context(e, "Error during packet capture")
            raise PluginError(f"Packet capture failed: {e}")
        finally:
            self._running = False
    
    def _safe_socket_command(self, command) -> bool:
        """Safely execute a socket command during shutdown."""
        try:
            # Check socket validity
            if not self.bt_socket or not hasattr(self.bt_socket, 'ins'):
                return False
            
            # Check if socket file descriptor is valid
            if hasattr(self.bt_socket.ins, 'fileno'):
                self.bt_socket.ins.fileno()
            
            # Execute the command
            self.bt_socket.sr(command, verbose=False)
            return True
            
        except (OSError, BrokenPipeError, ConnectionResetError, ValueError) as e:
            # Expected errors during shutdown
            logger.debug(f"Expected socket error during shutdown: {e}")
            return False
        except Exception as e:
            # Unexpected errors
            logger.debug(f"Unexpected error during socket command: {e}")
            return False
    
    def stop_capture(self) -> None:
        """Stop BLE capture."""
        self._running = False
        
        if self.bt_socket:
            # During shutdown, skip the disable command and just close the socket
            # This avoids "Bad file descriptor" errors from trying to send on a closed socket
            
            # Suppress all scapy logging during shutdown
            import logging
            scapy_logger = logging.getLogger("scapy")
            sendrecv_logger = logging.getLogger("scapy.sendrecv")
            supersocket_logger = logging.getLogger("scapy.supersocket")
            
            original_levels = {
                'scapy': scapy_logger.level,
                'sendrecv': sendrecv_logger.level,
                'supersocket': supersocket_logger.level
            }
            
            # Set all to CRITICAL to suppress errors
            scapy_logger.setLevel(logging.CRITICAL)
            sendrecv_logger.setLevel(logging.CRITICAL)
            supersocket_logger.setLevel(logging.CRITICAL)
            
            try:
                # Close socket immediately to interrupt sniff operations
                if hasattr(self.bt_socket, 'close'):
                    self.bt_socket.close()
                elif hasattr(self.bt_socket, 'ins'):
                    self.bt_socket.ins.close()
                logger.debug("BLE socket closed successfully")
            except Exception as e:
                logger.debug(f"Expected error closing socket: {e}")
            finally:
                # Restore original logging levels
                scapy_logger.setLevel(original_levels['scapy'])
                sendrecv_logger.setLevel(original_levels['sendrecv'])
                supersocket_logger.setLevel(original_levels['supersocket'])
        
        if self.company_resolver:
            self.company_resolver.close()
    
    def _handle_packet(self, packet, writers: Dict[str, PcapWriter]):
        """Handle captured packet and write to appropriate PCAP file."""
        try:
            if not packet.haslayer(HCI_LE_Meta_Advertising_Reports):
                return
            
            # Extract advertising reports
            reports = chain.from_iterable(
                p[HCI_LE_Meta_Advertising_Reports].reports for p in packet
            )
            
            for report in reports:
                self._process_advertising_report(report, packet, writers)
                
        except Exception as e:
            self.logger.error_with_context(e, "Error processing packet")
            self.stats.total_packets += 1
    
    def _process_advertising_report(self, report, original_packet, writers: Dict[str, PcapWriter]):
        """Process individual advertising report."""
        try:
            # Extract packet information
            packet_info = self.device_detector.extract_packet_info(report)
            if not packet_info or packet_info.rssi < self.min_rssi:
                return
            
            self.stats.total_packets += 1
            self.stats.valid_packets += 1
            
            # Get or create device
            device = self._get_or_create_device(packet_info)
            
            # Determine output file
            from ...config import config
            device_type_str = device.device_type.value
            is_special_device = device_type_str in config.device_types_for_devices_pcap
            is_known_company = (packet_info.company_id and 
                              self.device_detector.is_known_company(packet_info.company_id))
            
            if is_special_device:
                writers["special"].write(original_packet)
                if device.company_name:
                    self.stats.known_companies.add(device.company_name)
            elif is_known_company:
                writers["known"].write(original_packet)
                if device.company_name:
                    self.stats.known_companies.add(device.company_name)
            else:
                writers["unknown"].write(original_packet)
                if packet_info.company_id:
                    self.stats.unknown_company_ids.add(packet_info.company_id)
            
        except Exception as e:
            self.logger.error_with_context(e, "Error processing advertising report")
    
    def _get_or_create_device(self, packet_info: PacketInfo) -> BluetoothDevice:
        """Get existing device or create new one."""
        addr = packet_info.addr
        
        if addr in self.devices:
            device = self.devices[addr]
            device.update_seen(packet_info.rssi, packet_info.data, packet_info.device_name)
        else:
            device = self.device_detector.create_device(packet_info)
            self.devices[addr] = device
            self.stats.add_device(device)
            
            self.logger.device_detected(
                device.device_type.value, device.addr, device.rssi, 
                device.data, device.company_name
            )
        
        return device
    
    def process_packet(self, packet: Any) -> Optional[Dict[str, Any]]:
        """Process packet and extract device information."""
        # This is called by the main capture loop
        # Actual processing is done in _handle_packet for BLE
        return None
    
    def create_live_display(self) -> Layout:
        """Create BLE live display layout."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=8)
        )
        layout["main"].split_row(
            Layout(name="devices", ratio=2),
            Layout(name="stats", ratio=1)
        )
        return layout
    
    def update_display(self, layout: Layout) -> None:
        """Update BLE live display."""
        # Header
        sort_name = self.sort_modes[self.sort_mode][0]
        sort_dir = "↑" if self.sort_ascending else "↓"
        
        header = Panel(
            f"🔵 [bold bright_blue]BLE Scanner[/bold bright_blue] - "
            f"Interface: {self.interface} | "
            f"Devices: {len(self.devices)} | "
            f"Packets: {self.stats.total_packets:,} | "
            f"Sort: [yellow]{sort_name} {sort_dir}[/yellow]",
            style="bright_blue"
        )
        layout["header"].update(header)
        
        # Device table
        device_table = self._create_device_table()
        layout["devices"].update(Panel(device_table, title="🔍 BLE Devices", style="green"))
        
        # Statistics
        stats_panel = self._create_stats_panel()
        layout["stats"].update(stats_panel)
        
        # Footer
        footer = Panel(
            "[dim]Sort: [/dim]"
            "[bright_blue]R[/bright_blue]=[dim]RSSI[/dim] | "
            "[bright_blue]F[/bright_blue]=[dim]First Seen[/dim] | "
            "[bright_blue]L[/bright_blue]=[dim]Last Seen[/dim] | "
            "[bright_blue]T[/bright_blue]=[dim]Total Time[/dim] | "
            "[bright_blue]P[/bright_blue]=[dim]Packets[/dim]",
            style="dim"
        )
        layout["footer"].update(footer)
    
    def _create_device_table(self) -> Table:
        """Create BLE device table."""
        table = Table(show_header=True, header_style="bold bright_blue")
        table.add_column("Type", style="cyan", width=12)
        table.add_column("Address", style="white", width=17)
        table.add_column("RSSI", style="yellow", width=5, justify="right")
        table.add_column("Company", style="green", width=15)
        table.add_column("Pkts", style="magenta", width=4, justify="right")
        table.add_column("First", style="dim", width=8)
        table.add_column("Last", style="dim", width=8)
        table.add_column("Total", style="dim", width=8)
        
        # Sort devices
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
            
            # Format times
            last_seen_str = format_time_delta(last_seen_delta)
            if total_time_delta.total_seconds() < 3600:
                first_seen_str = device.first_seen.strftime("%H:%M:%S")
            else:
                first_seen_str = format_time_delta(total_time_delta) + " ago"
            total_time_str = format_time_delta(total_time_delta)
            
            # Color RSSI
            rssi_value, rssi_style = format_rssi_with_quality(device.rssi)
            
            table.add_row(
                device.device_type.value,
                device.addr,
                f"[{rssi_style}]{rssi_value}[/{rssi_style}]",
                device.company_name or "Unknown",
                str(device.packet_count),
                first_seen_str,
                last_seen_str,
                total_time_str
            )
        
        return table
    
    def _create_stats_panel(self) -> Panel:
        """Create BLE statistics panel."""
        duration = self.stats.session_duration_seconds
        rate = self.stats.packets_per_second
        
        stats_text = f"""📊 [bold]BLE Statistics[/bold]
        
🕐 Duration: {duration:.1f}s
📦 Packets: {self.stats.total_packets:,}
📱 Devices: {len(self.devices)}
⚡ Rate: {rate:.1f} pkt/s
❌ Error Rate: {self.stats.error_rate:.2%}

🏢 [bold]Companies[/bold]
✅ Known: {len(self.stats.known_companies)}
❓ Unknown: {len(self.stats.unknown_company_ids)}

🏷️ [bold]Device Types[/bold]"""
        
        for device_type, count in self.stats.devices_by_type.items():
            stats_text += f"\n{device_type.value}: {count}"
        
        return Panel(stats_text, title="📈 BLE Stats", style="yellow")
    
    
    def handle_keyboard_input(self, key: str) -> None:
        """Handle keyboard input for BLE plugin."""
        if key.lower() == 'r':
            if self.sort_mode == "rssi":
                self.sort_ascending = not self.sort_ascending
            else:
                self.sort_mode = "rssi"
                self.sort_ascending = False
        elif key.lower() == 'f':
            if self.sort_mode == "first_seen":
                self.sort_ascending = not self.sort_ascending
            else:
                self.sort_mode = "first_seen"
                self.sort_ascending = False
        elif key.lower() == 'l':
            if self.sort_mode == "last_seen":
                self.sort_ascending = not self.sort_ascending
            else:
                self.sort_mode = "last_seen"
                self.sort_ascending = False
        elif key.lower() == 't':
            if self.sort_mode == "total_time":
                self.sort_ascending = not self.sort_ascending
            else:
                self.sort_mode = "total_time"
                self.sort_ascending = False
        elif key.lower() == 'p':
            if self.sort_mode == "packets":
                self.sort_ascending = not self.sort_ascending
            else:
                self.sort_mode = "packets"
                self.sort_ascending = False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get BLE plugin statistics."""
        return {
            "protocol": "BLE",
            "interface": self.interface,
            "devices": len(self.devices),
            "packets": self.stats.total_packets,
            "valid_packets": self.stats.valid_packets,
            "error_rate": self.stats.error_rate,
            "packets_per_second": self.stats.packets_per_second,
            "known_companies": len(self.stats.known_companies),
            "unknown_companies": len(self.stats.unknown_company_ids),
            "device_types": {dt.value: count for dt, count in self.stats.devices_by_type.items()},
            "output_files": self._output_files
        }