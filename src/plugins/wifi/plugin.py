"""
WiFi packet capture plugin.
"""

import socket
import struct
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp
from scapy.utils import PcapWriter

from ...logger import BaconFreakLogger
from ...models import DeviceStats
from ..base import CapturePlugin, PluginError, PluginInfo, PluginRequirementError


class WiFiDevice:
    """Represents a detected WiFi device."""
    
    def __init__(self, bssid: str, ssid: str = "", device_type: str = "access_point"):
        self.bssid = bssid
        self.ssid = ssid or "Hidden"
        self.device_type = device_type  # access_point, client, probe
        self.channel = None
        self.rssi = -100
        self.encryption = "Unknown"
        self.vendor = "Unknown"
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.packet_count = 1
        self.data_packets = 0
        self.beacon_packets = 0
        self.probe_packets = 0
    
    def update_seen(self, rssi: Optional[int] = None, channel: Optional[int] = None, 
                   encryption: Optional[str] = None):
        """Update device last seen and stats."""
        self.last_seen = datetime.now()
        self.packet_count += 1
        
        if rssi is not None and rssi > self.rssi:
            self.rssi = rssi
        if channel is not None:
            self.channel = channel
        if encryption is not None:
            self.encryption = encryption


class WiFiPlugin(CapturePlugin):
    """WiFi packet capture plugin using monitor mode."""
    
    def __init__(self, config: Dict[str, Any], console: Optional[Console] = None):
        super().__init__(config, console)
        
        # WiFi-specific configuration
        self.interface = config.get("interface", "wlan0")
        self.monitor_mode = config.get("monitor_mode", True)
        self.scan_timeout = config.get("scan_timeout", 0)
        self.channel_hop = config.get("channel_hop", True)
        self.channels = config.get("channels", list(range(1, 14)))  # 2.4GHz channels
        self.min_rssi = config.get("min_rssi", -100)
        
        # WiFi-specific components
        self.logger = BaconFreakLogger("wifi_plugin")
        self.wifi_devices: Dict[str, WiFiDevice] = {}
        self.current_channel = 1
        self.channel_hop_interval = config.get("channel_hop_interval", 2.0)
        
        # UI state for sorting
        self.sort_mode = "last_seen"
        self.sort_ascending = False
        self.sort_modes = {
            "last_seen": ("Last Seen", lambda d: d.last_seen),
            "first_seen": ("First Seen", lambda d: d.first_seen),
            "rssi": ("RSSI", lambda d: d.rssi),
            "ssid": ("SSID", lambda d: d.ssid.lower()),
            "packets": ("Packets", lambda d: d.packet_count),
            "channel": ("Channel", lambda d: d.channel or 0)
        }
        
        # Capture state
        self._capture_socket = None
        self._channel_hop_thread = None
        self._output_files: Dict[str, Path] = {}
    
    @property
    def info(self) -> PluginInfo:
        """Return WiFi plugin information."""
        return PluginInfo(
            name="WiFi Scanner",
            version="1.0.0",
            description="WiFi packet capture and access point/client detection in monitor mode",
            protocol="wifi",
            requires_root=True,
            supported_platforms=["linux"],
            config_schema={
                "interface": {"type": "string", "default": "wlan0", "description": "WiFi interface name"},
                "monitor_mode": {"type": "boolean", "default": True, "description": "Enable monitor mode for packet capture"},
                "scan_timeout": {"type": "integer", "default": 0, "description": "Scan timeout (0=infinite)"},
                "channel_hop": {"type": "boolean", "default": True, "description": "Enable channel hopping"},
                "channels": {"type": "array", "default": [1, 6, 11], "description": "Channels to scan"},
                "min_rssi": {"type": "integer", "default": -100, "description": "Minimum RSSI threshold"},
                "channel_hop_interval": {"type": "number", "default": 2.0, "description": "Channel hop interval (seconds)"}
            }
        )
    
    def validate_config(self) -> tuple[bool, List[str]]:
        """Validate WiFi plugin configuration."""
        errors = []
        
        # Validate interface format and existence
        if not isinstance(self.interface, str) or not self.interface:
            errors.append("interface must be a non-empty string")
        else:
            # Check if interface exists and is a wireless interface
            if not self._is_valid_wifi_interface(self.interface):
                errors.append(f"interface '{self.interface}' is not a valid WiFi interface")
        
        if not isinstance(self.scan_timeout, int) or self.scan_timeout < 0:
            errors.append("scan_timeout must be a non-negative integer")
        
        if not isinstance(self.min_rssi, int) or self.min_rssi < -127 or self.min_rssi > 20:
            errors.append("min_rssi must be between -127 and 20")
        
        if not isinstance(self.channels, list) or not all(isinstance(c, int) and 1 <= c <= 165 for c in self.channels):
            errors.append("channels must be a list of integers between 1 and 165")
        
        return len(errors) == 0, errors
    
    def check_requirements(self) -> tuple[bool, List[str]]:
        """Check WiFi plugin requirements."""
        errors = []
        
        # Check root privileges
        import os
        if os.geteuid() != 0:
            errors.append("Root privileges required for WiFi monitor mode operations")
        
        # Check WiFi interface availability
        if not self._test_interface(self.interface):
            self._exit_with_interface_error()
        
        # Check if WiFi tools are available for monitor mode operations
        import shutil
        has_iw = shutil.which("iw")
        has_iwconfig = shutil.which("iwconfig")
        
        if not has_iw and not has_iwconfig:
            errors.append("Neither iw nor iwconfig commands available for WiFi operations")
            logger.info("Install with: sudo apt install iw wireless-tools")
        else:
            # Check if we can enable monitor mode using available tools
            try:
                if has_iw:
                    result = os.popen(f"iw dev {self.interface} info 2>/dev/null").read()
                    if result and "type monitor" not in result:
                        # Try to check if we can set monitor mode
                        test_result = os.popen(f"iw dev {self.interface} set type monitor 2>&1").read()
                        if "Operation not supported" in test_result:
                            errors.append(f"Interface {self.interface} does not support monitor mode")
                elif has_iwconfig:
                    # iwconfig doesn't have a clean way to test monitor mode support
                    # We'll just log that we're using iwconfig
                    logger.info(f"Using iwconfig for WiFi operations on {self.interface}")
            except Exception:
                logger.warning(f"Cannot check monitor mode capability for {self.interface}")
        
        return len(errors) == 0, errors
    
    def _is_valid_wifi_interface(self, interface_name: str) -> bool:
        """Check if interface is a valid WiFi interface using ip command."""
        import os
        
        try:
            # Check if interface exists using ip link
            result = os.popen(f"ip link show {interface_name} 2>/dev/null").read()
            if not result or "does not exist" in result or "LOOPBACK" in result:
                return False
            
            # Check if interface name follows WiFi naming conventions
            # Common WiFi interface patterns: wlan*, wlp*, wlx*, ath*, ra*, etc.
            wifi_patterns = ['wlan', 'wlp', 'wlx', 'ath', 'ra', 'wmaster', 'mon']
            return any(interface_name.startswith(pattern) for pattern in wifi_patterns)
                
        except Exception:
            return False
    
    def _test_interface(self, interface_name: str) -> bool:
        """Test if a WiFi interface is available and working."""
        import os
        try:
            # First check if it's a valid WiFi interface
            if not self._is_valid_wifi_interface(interface_name):
                return False
            
            # Check if interface is up or can be brought up
            result = os.popen(f"ip link show {interface_name} 2>/dev/null").read()
            return bool(result and "does not exist" not in result and "LOOPBACK" not in result)
        except Exception:
            return False
    
    def _exit_with_interface_error(self) -> None:
        """Print error message and exit when interface is not available."""
        from rich.console import Console
        from rich.panel import Panel
        from rich.text import Text
        import sys
        
        console = Console()
        
        error_text = Text()
        error_text.append("❌ WiFi Interface Error\n\n", style="bold red")
        error_text.append(f"WiFi interface {self.interface} is not available.\n\n", style="white")
        error_text.append("Solutions:\n", style="yellow")
        error_text.append("1. Check all network interfaces: ", style="white")
        error_text.append("ip link show\n", style="cyan")
        error_text.append("2. Enable the interface: ", style="white")
        error_text.append(f"sudo ip link set {self.interface} up\n", style="cyan")
        error_text.append("3. Check for WiFi hardware: ", style="white")
        error_text.append("lspci | grep -i wireless\n", style="cyan")
        error_text.append("4. Check USB WiFi adapters: ", style="white")
        error_text.append("lsusb | grep -i wireless\n", style="cyan")
        error_text.append("5. Install WiFi tools: ", style="white")
        error_text.append("sudo apt install iw wireless-tools\n", style="cyan")
        
        console.print(Panel(error_text, title="📶 WiFi Plugin", border_style="red"))
        sys.exit(1)
    
    def get_default_output_files(self, output_dir: Path) -> Dict[str, Path]:
        """Get default WiFi output file paths."""
        return {
            "beacon_frames": output_dir / self.get_timestamped_filename("wifi-beacons.pcap"),
            "probe_requests": output_dir / self.get_timestamped_filename("wifi-probes.pcap"),
            "data_frames": output_dir / self.get_timestamped_filename("wifi-data.pcap"),
            "all_frames": output_dir / self.get_timestamped_filename("wifi-all.pcap")
        }
    
    def initialize_capture(self) -> None:
        """Initialize WiFi capture in monitor mode."""
        import shutil
        
        try:
            # Set interface down
            os.system(f"ip link set {self.interface} down")
            
            # Set monitor mode - try iw first, fallback to iwconfig
            if shutil.which("iw"):
                result = os.system(f"iw dev {self.interface} set type monitor")
                if result != 0:
                    raise PluginError(f"Failed to set {self.interface} to monitor mode using iw")
            elif shutil.which("iwconfig"):
                result = os.system(f"iwconfig {self.interface} mode monitor")
                if result != 0:
                    raise PluginError(f"Failed to set {self.interface} to monitor mode using iwconfig")
            else:
                raise PluginError("Neither iw nor iwconfig commands available for monitor mode")
            
            # Bring interface up
            os.system(f"ip link set {self.interface} up")
            
            # Set initial channel
            if self.channels:
                self.current_channel = self.channels[0]
                self._set_channel(self.current_channel)
            
            logger.info(f"WiFi plugin initialized on {self.interface} (monitor mode)")
            
        except Exception as e:
            raise PluginError(f"Failed to initialize WiFi capture: {e}")
    
    def _set_channel(self, channel: int) -> bool:
        """Set WiFi channel using available tools."""
        import shutil
        
        try:
            if shutil.which("iw"):
                result = os.system(f"iw dev {self.interface} set channel {channel}")
                return result == 0
            elif shutil.which("iwconfig"):
                result = os.system(f"iwconfig {self.interface} channel {channel}")
                return result == 0
            else:
                logger.warning("No WiFi tools available for channel setting")
                return False
        except Exception as e:
            logger.warning(f"Failed to set channel {channel}: {e}")
            return False
    
    @contextmanager
    def _pcap_writers_context(self, output_files: Dict[str, Path]):
        """Context manager for WiFi PCAP writers."""
        writers = {}
        try:
            # Ensure output directory exists
            for file_path in output_files.values():
                file_path.parent.mkdir(parents=True, exist_ok=True)
            
            writers["beacon"] = PcapWriter(str(output_files["beacon_frames"]))
            writers["probe"] = PcapWriter(str(output_files["probe_requests"]))
            writers["data"] = PcapWriter(str(output_files["data_frames"]))
            writers["all"] = PcapWriter(str(output_files["all_frames"]))
            
            self._output_files = output_files
            yield writers
            
        finally:
            for writer in writers.values():
                if writer:
                    writer.close()
    
    def start_capture(self, packet_callback, stop_event) -> None:
        """Start WiFi packet capture."""
        self._running = True
        
        # Set up output files
        from ...config import config
        output_files = self.get_default_output_files(config.output_dir_path)
        
        try:
            with self._pcap_writers_context(output_files) as writers:
                # Start channel hopping if enabled
                if self.channel_hop and len(self.channels) > 1:
                    self._start_channel_hopping(stop_event)
                
                # Start packet capture
                def packet_handler(packet):
                    if stop_event.is_set():
                        return
                    
                    device_info = self.process_packet(packet)
                    if device_info:
                        packet_callback(device_info, packet)
                        self._write_packet_to_pcap(packet, writers)
                
                # Use scapy to sniff on the interface with responsive timeout
                # Use shorter timeouts to make sniff more responsive to stop signals
                sniff_timeout = min(5.0, self.scan_timeout) if self.scan_timeout > 0 else 5.0
                end_time = time.time() + self.scan_timeout if self.scan_timeout > 0 else None
                
                while self._running and not stop_event.is_set():
                    if end_time and time.time() >= end_time:
                        break
                    
                    try:
                        sniff(
                            iface=self.interface,
                            prn=packet_handler,
                            store=0,
                            stop_filter=lambda x: stop_event.is_set() or not self._running,
                            timeout=sniff_timeout
                        )
                    except Exception as e:
                        if "Interrupted system call" in str(e) or stop_event.is_set():
                            break
                        else:
                            raise
                
        except Exception as e:
            self.logger.error_with_context(e, "Error during WiFi packet capture")
            raise PluginError(f"WiFi packet capture failed: {e}")
        finally:
            self._stop_channel_hopping()
            self._running = False
    
    def stop_capture(self) -> None:
        """Stop WiFi capture and restore interface."""
        self._running = False
        self._stop_channel_hopping()
        
        try:
            # Restore interface to managed mode
            os.system(f"ip link set {self.interface} down")
            
            # Restore managed mode - try iw first, fallback to iwconfig
            import shutil
            if shutil.which("iw"):
                os.system(f"iw dev {self.interface} set type managed")
            elif shutil.which("iwconfig"):
                os.system(f"iwconfig {self.interface} mode managed")
            
            os.system(f"ip link set {self.interface} up")
        except:
            pass  # Ignore errors during cleanup
    
    def _start_channel_hopping(self, stop_event):
        """Start channel hopping thread."""
        def channel_hop_worker():
            channel_index = 0
            while self._running and not stop_event.is_set():
                if self.channels:
                    self.current_channel = self.channels[channel_index]
                    self._set_channel(self.current_channel)
                    channel_index = (channel_index + 1) % len(self.channels)
                
                time.sleep(self.channel_hop_interval)
        
        self._channel_hop_thread = threading.Thread(target=channel_hop_worker, daemon=True)
        self._channel_hop_thread.start()
    
    def _stop_channel_hopping(self):
        """Stop channel hopping thread."""
        if self._channel_hop_thread and self._channel_hop_thread.is_alive():
            self._channel_hop_thread = None
    
    def _write_packet_to_pcap(self, packet, writers: Dict[str, PcapWriter]):
        """Write packet to appropriate PCAP file based on type."""
        # Always write to all frames
        writers["all"].write(packet)
        
        if packet.haslayer(Dot11Beacon):
            writers["beacon"].write(packet)
        elif packet.haslayer(Dot11ProbeReq) or packet.haslayer(Dot11ProbeResp):
            writers["probe"].write(packet)
        elif packet.haslayer(Dot11) and packet.type == 2:  # Data frame
            writers["data"].write(packet)
    
    def process_packet(self, packet: Any) -> Optional[Dict[str, Any]]:
        """Process WiFi packet and extract device information."""
        try:
            if not packet.haslayer(Dot11):
                return None
            
            dot11 = packet[Dot11]
            rssi = None
            
            # Try to get RSSI from RadioTap if available
            if hasattr(packet, 'dBm_AntSignal'):
                rssi = packet.dBm_AntSignal
            elif hasattr(packet, 'RadioTap') and hasattr(packet.RadioTap, 'dBm_AntSignal'):
                rssi = packet.RadioTap.dBm_AntSignal
            
            # Skip if RSSI is below threshold
            if rssi is not None and rssi < self.min_rssi:
                return None
            
            self.stats.total_packets += 1
            
            # Process different frame types
            device_info = None
            
            if packet.haslayer(Dot11Beacon):
                device_info = self._process_beacon(packet, rssi)
            elif packet.haslayer(Dot11ProbeReq):
                device_info = self._process_probe_request(packet, rssi)
            elif packet.haslayer(Dot11ProbeResp):
                device_info = self._process_probe_response(packet, rssi)
            elif dot11.type == 2:  # Data frame
                device_info = self._process_data_frame(packet, rssi)
            
            if device_info:
                self.stats.valid_packets += 1
            
            return device_info
            
        except Exception as e:
            self.logger.error_with_context(e, "Error processing WiFi packet")
            return None
    
    def _process_beacon(self, packet, rssi: Optional[int]) -> Optional[Dict[str, Any]]:
        """Process 802.11 beacon frame."""
        try:
            beacon = packet[Dot11Beacon]
            bssid = packet[Dot11].addr3
            
            # Extract SSID
            ssid = ""
            if hasattr(beacon, 'info') and beacon.info:
                ssid = beacon.info.decode('utf-8', errors='ignore')
            
            # Extract channel from DS Parameter Set
            channel = None
            if hasattr(beacon, 'network_stats') and hasattr(beacon.network_stats, 'channel'):
                channel = beacon.network_stats.channel
            
            # Update or create access point
            device = self._get_or_create_wifi_device(bssid, ssid, "access_point")
            device.update_seen(rssi, channel)
            device.beacon_packets += 1
            
            return {
                "type": "beacon",
                "bssid": bssid,
                "ssid": ssid,
                "channel": channel,
                "rssi": rssi
            }
            
        except Exception as e:
            self.logger.error_with_context(e, "Error processing beacon frame")
            return None
    
    def _process_probe_request(self, packet, rssi: Optional[int]) -> Optional[Dict[str, Any]]:
        """Process 802.11 probe request frame."""
        try:
            client_mac = packet[Dot11].addr2
            
            # Extract requested SSID
            ssid = ""
            if hasattr(packet[Dot11ProbeReq], 'info') and packet[Dot11ProbeReq].info:
                ssid = packet[Dot11ProbeReq].info.decode('utf-8', errors='ignore')
            
            # Update or create client device
            device = self._get_or_create_wifi_device(client_mac, f"Client-{ssid}", "client")
            device.update_seen(rssi)
            device.probe_packets += 1
            
            return {
                "type": "probe_request",
                "client_mac": client_mac,
                "requested_ssid": ssid,
                "rssi": rssi
            }
            
        except Exception as e:
            self.logger.error_with_context(e, "Error processing probe request")
            return None
    
    def _process_probe_response(self, packet, rssi: Optional[int]) -> Optional[Dict[str, Any]]:
        """Process 802.11 probe response frame."""
        try:
            bssid = packet[Dot11].addr3
            
            # Extract SSID
            ssid = ""
            if hasattr(packet[Dot11ProbeResp], 'info') and packet[Dot11ProbeResp].info:
                ssid = packet[Dot11ProbeResp].info.decode('utf-8', errors='ignore')
            
            # Update or create access point
            device = self._get_or_create_wifi_device(bssid, ssid, "access_point")
            device.update_seen(rssi)
            device.probe_packets += 1
            
            return {
                "type": "probe_response",
                "bssid": bssid,
                "ssid": ssid,
                "rssi": rssi
            }
            
        except Exception as e:
            self.logger.error_with_context(e, "Error processing probe response")
            return None
    
    def _process_data_frame(self, packet, rssi: Optional[int]) -> Optional[Dict[str, Any]]:
        """Process 802.11 data frame."""
        try:
            # Data frames can help identify active clients
            client_mac = packet[Dot11].addr2
            ap_mac = packet[Dot11].addr1
            
            # Update client if we see data from it
            if client_mac and client_mac != ap_mac:
                device = self._get_or_create_wifi_device(client_mac, "Data-Client", "client")
                device.update_seen(rssi)
                device.data_packets += 1
            
            return {
                "type": "data",
                "client_mac": client_mac,
                "ap_mac": ap_mac,
                "rssi": rssi
            }
            
        except Exception as e:
            self.logger.error_with_context(e, "Error processing data frame")
            return None
    
    def _get_or_create_wifi_device(self, mac: str, ssid: str, device_type: str) -> WiFiDevice:
        """Get existing WiFi device or create new one."""
        if mac in self.wifi_devices:
            device = self.wifi_devices[mac]
            # Update SSID if we got a better one
            if ssid and ssid != "Hidden" and device.ssid in ["Hidden", "", f"Client-", f"Data-Client"]:
                device.ssid = ssid
        else:
            device = WiFiDevice(mac, ssid, device_type)
            self.wifi_devices[mac] = device
            
            self.logger.device_detected(
                device_type, mac, device.rssi, {"ssid": ssid}, "WiFi"
            )
        
        return device
    
    def create_live_display(self) -> Layout:
        """Create WiFi live display layout."""
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
        """Update WiFi live display."""
        # Header
        sort_name = self.sort_modes[self.sort_mode][0]
        sort_dir = "↑" if self.sort_ascending else "↓"
        
        header = Panel(
            f"📶 [bold bright_green]WiFi Scanner[/bold bright_green] - "
            f"Interface: {self.interface} | "
            f"Channel: {self.current_channel} | "
            f"Devices: {len(self.wifi_devices)} | "
            f"Packets: {self.stats.total_packets:,} | "
            f"Sort: [yellow]{sort_name} {sort_dir}[/yellow]",
            style="bright_green"
        )
        layout["header"].update(header)
        
        # Device table
        device_table = self._create_device_table()
        layout["devices"].update(Panel(device_table, title="📡 WiFi Devices", style="green"))
        
        # Statistics
        stats_panel = self._create_stats_panel()
        layout["stats"].update(stats_panel)
        
        # Footer
        footer = Panel(
            "[dim]Controls: [/dim]"
            "[bright_green]S[/bright_green]=[dim]SSID[/dim] | "
            "[bright_green]R[/bright_green]=[dim]RSSI[/dim] | "
            "[bright_green]C[/bright_green]=[dim]Channel[/dim] | "
            "[bright_green]F[/bright_green]=[dim]First Seen[/dim] | "
            "[bright_green]L[/bright_green]=[dim]Last Seen[/dim] | "
            "[bright_green]P[/bright_green]=[dim]Packets[/dim] | "
            "[red]Ctrl+C[/red]=[dim]Quit[/dim]",
            style="dim"
        )
        layout["footer"].update(footer)
    
    def _create_device_table(self) -> Table:
        """Create WiFi device table."""
        table = Table(show_header=True, header_style="bold bright_green")
        table.add_column("Type", style="cyan", width=8)
        table.add_column("MAC Address", style="white", width=17)
        table.add_column("SSID", style="yellow", width=20)
        table.add_column("Ch", style="magenta", width=3, justify="right")
        table.add_column("RSSI", style="yellow", width=5, justify="right")
        table.add_column("Pkts", style="magenta", width=4, justify="right")
        table.add_column("First", style="dim", width=8)
        table.add_column("Last", style="dim", width=8)
        
        # Sort devices
        if self.wifi_devices:
            sort_key = self.sort_modes[self.sort_mode][1]
            recent_devices = sorted(
                self.wifi_devices.values(),
                key=sort_key,
                reverse=not self.sort_ascending
            )[:20]
        else:
            recent_devices = []
        
        for device in recent_devices:
            now = datetime.now()
            last_seen_delta = now - device.last_seen
            first_seen_delta = now - device.first_seen
            
            # Format times
            last_seen_str = self._format_time_delta(last_seen_delta)
            if first_seen_delta.total_seconds() < 3600:
                first_seen_str = device.first_seen.strftime("%H:%M:%S")
            else:
                first_seen_str = self._format_time_delta(first_seen_delta) + " ago"
            
            # Color RSSI
            rssi_style = ("green" if device.rssi > -50 else 
                         "yellow" if device.rssi > -70 else "red")
            
            # Truncate long SSIDs
            ssid_display = device.ssid
            if len(ssid_display) > 18:
                ssid_display = ssid_display[:15] + "..."
            
            table.add_row(
                "AP" if device.device_type == "access_point" else "Client",
                device.bssid,
                ssid_display,
                str(device.channel) if device.channel else "-",
                f"[{rssi_style}]{device.rssi}[/{rssi_style}]" if device.rssi > -100 else "-",
                str(device.packet_count),
                first_seen_str,
                last_seen_str
            )
        
        return table
    
    def _create_stats_panel(self) -> Panel:
        """Create WiFi statistics panel."""
        duration = self.stats.session_duration_seconds
        rate = self.stats.packets_per_second
        
        # Count device types
        ap_count = sum(1 for d in self.wifi_devices.values() if d.device_type == "access_point")
        client_count = sum(1 for d in self.wifi_devices.values() if d.device_type == "client")
        
        # Count frame types
        beacon_count = sum(d.beacon_packets for d in self.wifi_devices.values())
        probe_count = sum(d.probe_packets for d in self.wifi_devices.values())
        data_count = sum(d.data_packets for d in self.wifi_devices.values())
        
        stats_text = f"""📊 [bold]WiFi Statistics[/bold]
        
🕐 Duration: {duration:.1f}s
📦 Packets: {self.stats.total_packets:,}
📡 Devices: {len(self.wifi_devices)}
⚡ Rate: {rate:.1f} pkt/s
❌ Error Rate: {self.stats.error_rate:.2%}

📱 [bold]Device Types[/bold]
🏢 Access Points: {ap_count}
👤 Clients: {client_count}

📋 [bold]Frame Types[/bold]
🗼 Beacons: {beacon_count}
🔍 Probes: {probe_count}
📊 Data: {data_count}

📶 [bold]Current Channel: {self.current_channel}[/bold]"""
        
        return Panel(stats_text, title="📈 WiFi Stats", style="yellow")
    
    def _format_time_delta(self, delta) -> str:
        """Format timedelta to human readable string."""
        total_seconds = int(delta.total_seconds())
        
        if total_seconds < 60:
            return f"{total_seconds}s"
        elif total_seconds < 3600:
            minutes = total_seconds // 60
            return f"{minutes}m"
        elif total_seconds < 86400:
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            return f"{hours}h{minutes}m" if minutes > 0 else f"{hours}h"
        else:
            days = total_seconds // 86400
            hours = (total_seconds % 86400) // 3600
            return f"{days}d{hours}h" if hours > 0 else f"{days}d"
    
    def handle_keyboard_input(self, key: str) -> None:
        """Handle keyboard input for WiFi plugin."""
        if key.lower() == 's':
            if self.sort_mode == "ssid":
                self.sort_ascending = not self.sort_ascending
            else:
                self.sort_mode = "ssid"
                self.sort_ascending = True
        elif key.lower() == 'r':
            if self.sort_mode == "rssi":
                self.sort_ascending = not self.sort_ascending
            else:
                self.sort_mode = "rssi"
                self.sort_ascending = False
        elif key.lower() == 'c':
            if self.sort_mode == "channel":
                self.sort_ascending = not self.sort_ascending
            else:
                self.sort_mode = "channel"
                self.sort_ascending = True
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
        elif key.lower() == 'p':
            if self.sort_mode == "packets":
                self.sort_ascending = not self.sort_ascending
            else:
                self.sort_mode = "packets"
                self.sort_ascending = False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get WiFi plugin statistics."""
        ap_count = sum(1 for d in self.wifi_devices.values() if d.device_type == "access_point")
        client_count = sum(1 for d in self.wifi_devices.values() if d.device_type == "client")
        
        return {
            "protocol": "WiFi",
            "interface": self.interface,
            "current_channel": self.current_channel,
            "devices": len(self.wifi_devices),
            "access_points": ap_count,
            "clients": client_count,
            "packets": self.stats.total_packets,
            "valid_packets": self.stats.valid_packets,
            "error_rate": self.stats.error_rate,
            "packets_per_second": self.stats.packets_per_second,
            "beacon_packets": sum(d.beacon_packets for d in self.wifi_devices.values()),
            "probe_packets": sum(d.probe_packets for d in self.wifi_devices.values()),
            "data_packets": sum(d.data_packets for d in self.wifi_devices.values()),
            "output_files": self._output_files
        }