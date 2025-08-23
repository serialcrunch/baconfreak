"""
WiFi packet capture plugin.
"""

import os
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
from rich.text import Text
from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp
from scapy.utils import PcapWriter

from ...logger import BaconFreakLogger
from ...utils import truncate_string
from ..base import CapturePlugin, PluginError, PluginInfo
from ..common_ui import SortManager, DeviceTableFormatter, StatsFormatter, TableColumnConfig, FooterBuilder
from ..interface_utils import InterfaceValidator, InterfaceErrorHandler, RequirementsChecker
from ..pcap_utils import PcapManager
from .oui_identifiers_unified import OUIIdentifiers


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

    def update_seen(
        self,
        rssi: Optional[int] = None,
        channel: Optional[int] = None,
        encryption: Optional[str] = None,
    ):
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

        # Initialize band support cache
        self._supported_bands = None

        # WiFi-specific components (initialize early for use in config methods)
        self.logger = BaconFreakLogger("wifi_plugin")
        
        # Initialize OUI identifier lookup
        self.oui_identifiers: Optional[OUIIdentifiers] = None

        # WiFi-specific configuration
        self.interface = config.get("interface", "wlan0")
        self.monitor_mode = config.get("monitor_mode", True)
        self.scan_timeout = config.get("scan_timeout", 0)
        self.channel_hop = config.get("channel_hop", True)
        self.enable_2_4ghz = config.get("enable_2_4ghz", True)
        self.enable_5ghz = config.get("enable_5ghz", False)
        self.enable_6e = config.get("enable_6e", False)
        self.channels = self._build_channel_list(config)
        self.min_rssi = config.get("min_rssi", -100)
        self.wifi_devices: Dict[str, WiFiDevice] = {}
        self.current_channel = 1
        self.channel_hop_interval = config.get("channel_hop_interval", 2.0)

        # UI state for sorting
        self.sort_manager = SortManager("last_seen", False)
        self.sort_manager.register_sort_mode("last_seen", "Last Seen", lambda d: d.last_seen)
        self.sort_manager.register_sort_mode("first_seen", "First Seen", lambda d: d.first_seen)
        self.sort_manager.register_sort_mode("rssi", "RSSI", lambda d: d.rssi)
        self.sort_manager.register_sort_mode("ssid", "SSID", lambda d: d.ssid.lower())
        self.sort_manager.register_sort_mode("packets", "Packets", lambda d: d.packet_count)
        self.sort_manager.register_sort_mode("channel", "Channel", lambda d: d.channel or 0)
        self.sort_manager.register_sort_mode("total_time", "Total Time", lambda d: (datetime.now() - d.first_seen).total_seconds())

        # Capture state
        self._capture_socket = None
        self._channel_hop_thread = None
        self._output_files: Dict[str, Path] = {}

    def _get_supported_bands(self) -> Dict[str, bool]:
        """Detect which WiFi bands the adapter supports."""
        if self._supported_bands is not None:
            return self._supported_bands

        import shutil
        import subprocess

        bands = {"2.4ghz": True, "5ghz": False, "6e": False}  # 2.4GHz always assumed supported

        try:
            # Try to get interface capabilities using iw
            if shutil.which("iw"):
                # First try to get the PHY for this interface
                phy_result = subprocess.run(
                    ["iw", "dev", self.interface, "info"], capture_output=True, text=True, timeout=5
                )

                phy_name = None
                if phy_result.returncode == 0:
                    # Extract PHY name from output
                    for line in phy_result.stdout.split("\n"):
                        if "wiphy" in line.lower():
                            parts = line.split()
                            for i, part in enumerate(parts):
                                if part == "wiphy" and i + 1 < len(parts):
                                    phy_name = f"phy{parts[i + 1]}"
                                    break
                            break

                # Get detailed frequency information from PHY
                phy_cmd = ["iw", "phy"]
                if phy_name:
                    phy_cmd.append(phy_name)
                phy_cmd.append("info")

                result = subprocess.run(phy_cmd, capture_output=True, text=True, timeout=5)

                if result.returncode == 0:
                    output = result.stdout

                    # Look for specific 5GHz frequency ranges
                    # 5GHz band: 5170-5825 MHz (channels 34-165)
                    fiveghz_frequencies = [
                        "5170",
                        "5180",
                        "5190",
                        "5200",
                        "5210",
                        "5220",
                        "5230",
                        "5240",  # UNII-1
                        "5250",
                        "5260",
                        "5270",
                        "5280",
                        "5290",
                        "5300",
                        "5310",
                        "5320",  # UNII-2A
                        "5500",
                        "5510",
                        "5520",
                        "5530",
                        "5540",
                        "5550",
                        "5560",
                        "5570",  # UNII-2B
                        "5580",
                        "5590",
                        "5600",
                        "5610",
                        "5620",
                        "5630",
                        "5640",
                        "5660",  # UNII-2C
                        "5670",
                        "5680",
                        "5690",
                        "5700",
                        "5710",
                        "5720",
                        "5745",
                        "5755",  # UNII-3
                        "5765",
                        "5775",
                        "5785",
                        "5795",
                        "5805",
                        "5815",
                        "5825",  # UNII-3
                    ]

                    # 6E band: 5925-7125 MHz (6GHz)
                    sixe_frequencies = [
                        "5925",
                        "5935",
                        "5945",
                        "5955",
                        "5965",
                        "5975",
                        "5985",
                        "5995",
                        "6005",
                        "6015",
                        "6025",
                        "6035",
                        "6045",
                        "6055",
                        "6065",
                        "6075",
                        "6085",
                        "6095",
                        "6105",
                        "6115",
                        "6125",
                        "6135",
                        "6145",
                        "6155",
                        "6165",
                        "6175",
                        "6185",
                        "6195",
                        "6205",
                        "6215",
                        "6225",
                        "6235",
                        "6245",
                        "6255",
                        "6265",
                        "6275",
                        "6285",
                        "6295",
                        "6305",
                        "6315",
                        "6325",
                        "6335",
                        "6345",
                        "6355",
                        "6365",
                        "6375",
                        "6385",
                        "6395",
                        "6405",
                        "6415",
                        "6425",
                        "6435",
                        "6445",
                        "6455",
                        "6465",
                        "6475",
                        "6485",
                        "6495",
                        "6505",
                        "6515",
                        "6525",
                        "6535",
                        "6545",
                        "6555",
                        "6565",
                        "6575",
                        "6585",
                        "6595",
                        "6605",
                        "6615",
                        "6625",
                        "6635",
                        "6645",
                        "6655",
                        "6665",
                        "6675",
                        "6685",
                        "6695",
                        "6705",
                        "6715",
                        "6725",
                        "6735",
                        "6745",
                        "6755",
                        "6765",
                        "6775",
                        "6785",
                        "6795",
                        "6805",
                        "6815",
                        "6825",
                        "6835",
                        "6845",
                        "6855",
                        "6865",
                        "6875",
                        "6885",
                        "6895",
                        "6905",
                        "6915",
                        "6925",
                        "6935",
                        "6945",
                        "6955",
                        "6965",
                        "6975",
                        "6985",
                        "6995",
                        "7005",
                        "7015",
                        "7025",
                        "7035",
                        "7045",
                        "7055",
                        "7065",
                        "7075",
                        "7085",
                        "7095",
                        "7105",
                        "7115",
                    ]

                    # Check for 5GHz support (need at least 3 frequencies for reliable detection)
                    fiveghz_matches = sum(1 for freq in fiveghz_frequencies if freq in output)
                    if fiveghz_matches >= 3:
                        bands["5ghz"] = True

                    # Check for 6E support (need at least 5 frequencies for reliable detection)
                    sixe_matches = sum(1 for freq in sixe_frequencies if freq in output)
                    if sixe_matches >= 5:
                        bands["6e"] = True

        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError) as e:
            logger.debug(f"Could not detect band support via iw: {e}")

        self._supported_bands = bands
        return bands

    def _build_channel_list(self, config: dict) -> List[int]:
        """Build channel list based on configuration and adapter capabilities."""
        # If manual channels are specified, use them directly
        manual_channels = config.get("channels")
        if manual_channels and isinstance(manual_channels, list) and len(manual_channels) > 0:
            # Filter out the default [1, 6, 11] if user wants band-based selection
            if not (len(manual_channels) == 3 and manual_channels == [1, 6, 11]):
                return manual_channels

        # Build channels based on enabled bands
        channels = []
        supported_bands = self._get_supported_bands()

        # 2.4GHz channels (1-14, commonly 1-11 in US)
        if self.enable_2_4ghz:
            if supported_bands["2.4ghz"]:
                channels.extend([1, 6, 11])  # Most common 2.4GHz channels
                logger.info("Added 2.4GHz channels to scan list")
            else:
                logger.warning(
                    "2.4GHz band requested but not supported by adapter, skipping 2.4GHz channels"
                )

        # 5GHz channels
        if self.enable_5ghz:
            if supported_bands["5ghz"]:
                # Common 5GHz channels (UNII-1, UNII-2, UNII-3)
                fiveghz_channels = [
                    36,
                    40,
                    44,
                    48,
                    52,
                    56,
                    60,
                    64,
                    100,
                    104,
                    108,
                    112,
                    116,
                    120,
                    124,
                    128,
                    132,
                    136,
                    140,
                    144,
                    149,
                    153,
                    157,
                    161,
                    165,
                ]
                channels.extend(fiveghz_channels)
                logger.info("Added 5GHz channels to scan list")
            else:
                logger.warning(
                    "5GHz band requested but not supported by adapter, skipping 5GHz channels"
                )

        # 6E channels
        if self.enable_6e:
            if supported_bands["6e"]:
                # Common 6GHz channels (actual channel numbers, not offset)
                # 6GHz channels: 1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93
                sixe_channels = [
                    1,
                    5,
                    9,
                    13,
                    17,
                    21,
                    25,
                    29,
                    33,
                    37,
                    41,
                    45,
                    49,
                    53,
                    57,
                    61,
                    65,
                    69,
                    73,
                    77,
                    81,
                    85,
                    89,
                    93,
                ]
                channels.extend(sixe_channels)
                logger.info("Added 6E channels to scan list")
            else:
                logger.warning(
                    "6E band requested but not supported by adapter, skipping 6E channels"
                )

        # Fallback: if no channels are enabled, enable 2.4GHz as default
        if not channels:
            logger.warning("No channels enabled, falling back to 2.4GHz channels")
            channels.extend([1, 6, 11])

        return sorted(list(set(channels)))  # Remove duplicates and sort

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
                "enabled": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enable/disable plugin",
                },
                "interface": {
                    "type": "string",
                    "default": "wlan0",
                    "description": "WiFi interface name",
                },
                "monitor_mode": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enable monitor mode for packet capture",
                },
                "scan_timeout": {
                    "type": "integer",
                    "default": 0,
                    "description": "Scan timeout (0=infinite)",
                },
                "channel_hop": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enable channel hopping",
                },
                "channels": {
                    "type": "array",
                    "default": [1, 6, 11],
                    "description": "Manual channel list (overrides band settings)",
                },
                "enable_2_4ghz": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enable 2.4GHz band channels",
                },
                "enable_5ghz": {
                    "type": "boolean",
                    "default": False,
                    "description": "Enable 5GHz band channels",
                },
                "enable_6e": {
                    "type": "boolean",
                    "default": False,
                    "description": "Enable 6E band channels",
                },
                "min_rssi": {
                    "type": "integer",
                    "default": -100,
                    "description": "Minimum RSSI threshold",
                },
                "channel_hop_interval": {
                    "type": "number",
                    "default": 2.0,
                    "description": "Channel hop interval (seconds)",
                },
            },
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

        if not isinstance(self.channels, list) or not all(
            isinstance(c, int) and 1 <= c <= 300 for c in self.channels
        ):
            errors.append(
                "channels must be a list of integers between 1 and 300 (includes 6E band)"
            )

        if not isinstance(self.enable_2_4ghz, bool):
            errors.append("enable_2_4ghz must be a boolean")

        if not isinstance(self.enable_5ghz, bool):
            errors.append("enable_5ghz must be a boolean")

        if not isinstance(self.enable_6e, bool):
            errors.append("enable_6e must be a boolean")

        return len(errors) == 0, errors

    def check_requirements(self) -> tuple[bool, List[str]]:
        """Check WiFi plugin requirements."""
        errors = []

        # Check root privileges
        root_ok, root_errors = RequirementsChecker.check_root_privileges()
        if not root_ok:
            errors.extend(["Root privileges required for WiFi monitor mode operations"])

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
                        test_result = os.popen(
                            f"iw dev {self.interface} set type monitor 2>&1"
                        ).read()
                        if "Operation not supported" in test_result:
                            errors.append(
                                f"Interface {self.interface} does not support monitor mode"
                            )
                elif has_iwconfig:
                    # iwconfig doesn't have a clean way to test monitor mode support
                    # We'll just log that we're using iwconfig
                    logger.info(f"Using iwconfig for WiFi operations on {self.interface}")
            except Exception:
                logger.warning(f"Cannot check monitor mode capability for {self.interface}")

        return len(errors) == 0, errors

    def _is_valid_wifi_interface(self, interface_name: str) -> bool:
        """Check if interface is a valid WiFi interface using ip command."""
        return InterfaceValidator.is_valid_wifi_interface(interface_name)

    def _test_interface(self, interface_name: str) -> bool:
        """Test if a WiFi interface is available and working."""
        return InterfaceValidator.test_wifi_interface(interface_name)

    def _exit_with_interface_error(self) -> None:
        """Print error message and exit when interface is not available."""
        InterfaceErrorHandler.exit_with_wifi_error(self.interface)

    def get_default_output_files(self, output_dir: Path) -> Dict[str, Path]:
        """Get default WiFi output file paths."""
        return {
            "beacon_frames": output_dir / self.get_timestamped_filename("wifi-beacons.pcap"),
            "probe_requests": output_dir / self.get_timestamped_filename("wifi-probes.pcap"),
            "data_frames": output_dir / self.get_timestamped_filename("wifi-data.pcap"),
            "all_frames": output_dir / self.get_timestamped_filename("wifi-all.pcap"),
        }

    def initialize_capture(self) -> None:
        """Initialize WiFi capture in monitor mode."""
        import shutil

        try:
            # Initialize OUI identifiers
            self.oui_identifiers = OUIIdentifiers()
            logger.info("OUI identifiers initialized for WiFi plugin")
            
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
                    raise PluginError(
                        f"Failed to set {self.interface} to monitor mode using iwconfig"
                    )
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
        with PcapManager.pcap_writers_context({
            "beacon": output_files["beacon_frames"],
            "probe": output_files["probe_requests"],
            "data": output_files["data_frames"],
            "all": output_files["all_frames"]
        }) as writers:
            self._output_files = output_files
            yield writers

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
                            timeout=sniff_timeout,
                        )
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
            logger.debug("KeyboardInterrupt in WiFi capture, propagating...")
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

                # Sleep in smaller increments to be more responsive to stop events
                sleep_time = self.channel_hop_interval
                sleep_increment = 0.1  # Check stop event every 100ms
                while sleep_time > 0 and self._running and not stop_event.is_set():
                    time.sleep(min(sleep_increment, sleep_time))
                    sleep_time -= sleep_increment

        self._channel_hop_thread = threading.Thread(target=channel_hop_worker, daemon=True)
        self._channel_hop_thread.start()

    def _stop_channel_hopping(self):
        """Stop channel hopping thread."""
        if self._channel_hop_thread and self._channel_hop_thread.is_alive():
            # Wait for thread to finish (it should exit quickly due to responsive sleep)
            self._channel_hop_thread.join(timeout=0.5)
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
            if hasattr(packet, "dBm_AntSignal"):
                rssi = packet.dBm_AntSignal
            elif hasattr(packet, "RadioTap") and hasattr(packet.RadioTap, "dBm_AntSignal"):
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
            if hasattr(beacon, "info") and beacon.info:
                ssid = beacon.info.decode("utf-8", errors="ignore")

            # Extract channel information
            channel = self._extract_channel_from_packet(packet)

            # Update or create access point
            device = self._get_or_create_wifi_device(bssid, ssid, "access_point")
            device.update_seen(rssi, channel)
            device.beacon_packets += 1

            return {
                "type": "beacon",
                "bssid": bssid,
                "ssid": ssid,
                "channel": channel,
                "rssi": rssi,
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
            if hasattr(packet[Dot11ProbeReq], "info") and packet[Dot11ProbeReq].info:
                ssid = packet[Dot11ProbeReq].info.decode("utf-8", errors="ignore")

            # Update or create client device
            device = self._get_or_create_wifi_device(
                client_mac, "Client", "client"
            )
            device.update_seen(rssi)
            device.probe_packets += 1

            return {
                "type": "probe_request",
                "client_mac": client_mac,
                "requested_ssid": ssid,
                "rssi": rssi,
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
            if hasattr(packet[Dot11ProbeResp], "info") and packet[Dot11ProbeResp].info:
                ssid = packet[Dot11ProbeResp].info.decode("utf-8", errors="ignore")

            # Extract channel information
            channel = self._extract_channel_from_packet(packet)

            # Update or create access point
            device = self._get_or_create_wifi_device(bssid, ssid, "access_point")
            device.update_seen(rssi, channel)
            device.probe_packets += 1

            return {
                "type": "probe_response",
                "bssid": bssid,
                "ssid": ssid,
                "channel": channel,
                "rssi": rssi,
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
                device = self._get_or_create_wifi_device(
                    client_mac, "Client (Data Frame)", "client"
                )
                device.update_seen(rssi)
                device.data_packets += 1

            return {"type": "data", "client_mac": client_mac, "ap_mac": ap_mac, "rssi": rssi}

        except Exception as e:
            self.logger.error_with_context(e, "Error processing data frame")
            return None

    def _get_or_create_wifi_device(self, mac: str, ssid: str, device_type: str) -> WiFiDevice:
        """Get existing WiFi device or create new one."""
        if mac in self.wifi_devices:
            device = self.wifi_devices[mac]
            # Update SSID if we got a better one
            if ssid and ssid != "Hidden" and device.ssid in ["Hidden", "", f"Client-", f"Client ("]:
                device.ssid = ssid
        else:
            device = WiFiDevice(mac, ssid, device_type)
            
            # Lookup vendor using OUI
            if self.oui_identifiers:
                try:
                    vendor = self.oui_identifiers.lookup_vendor(mac)
                    if vendor:
                        device.vendor = vendor
                        logger.debug(f"OUI lookup for {mac}: {vendor}")
                    else:
                        logger.debug(f"No OUI found for {mac}")
                except Exception as e:
                    logger.error(f"OUI lookup failed for {mac}: {e}")
            
            self.wifi_devices[mac] = device
            self.logger.device_detected(device_type, mac, device.rssi, ssid, "WiFi")

        return device

    def create_live_display(self) -> Layout:
        """Create WiFi live display layout."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3), Layout(name="main"), Layout(name="footer", size=8)
        )
        layout["main"].split_row(Layout(name="devices", ratio=2), Layout(name="stats", ratio=1))
        return layout

    def update_display(self, layout: Layout) -> None:
        """Update WiFi live display."""
        # Header
        sort_display = self.sort_manager.get_sort_display()

        header = Panel(
            f"[bold bright_green]WiFi Scanner[/bold bright_green] - "
            f"Interface: {self.interface} | "
            f"Channel: {self.current_channel} | "
            f"Devices: {len(self.wifi_devices)} | "
            f"Packets: {self.stats.total_packets:,} | "
            f"Sort: [yellow]{sort_display}[/yellow]",
            style="bright_green",
        )
        layout["header"].update(header)

        # Device table
        device_table = self._create_device_table()
        layout["devices"].update(Panel(device_table, title="WiFi Devices", style="green"))

        # Statistics
        stats_panel = self._create_stats_panel()
        layout["stats"].update(stats_panel)

        # Footer
        sort_keys = {
            "S": "SSID",
            "R": "RSSI",
            "C": "Channel", 
            "F": "First Seen",
            "L": "Last Seen",
            "T": "Total Time",
            "P": "Packets"
        }
        footer = FooterBuilder.create_sort_footer(sort_keys)
        layout["footer"].update(footer)

    def _create_device_table(self) -> Table:
        """Create WiFi device table."""
        table = Table(show_header=True, header_style="bold bright_green")
        
        # Add standard columns with WiFi-specific customization
        table.add_column("Type", style="cyan", width=8)
        TableColumnConfig.add_standard_column(table, "bssid", "MAC Address")
        table.add_column("SSID", style="yellow", width=20) 
        table.add_column("Ch", style="magenta", width=4, justify="right")
        table.add_column("Vendor", style="green", width=15)
        TableColumnConfig.add_standard_column(table, "rssi")
        table.add_column("Pkts", style="magenta", width=4, justify="right")
        TableColumnConfig.add_standard_column(table, "first_seen", "First")
        TableColumnConfig.add_standard_column(table, "last_seen", "Last")
        TableColumnConfig.add_standard_column(table, "total_time", "Total")

        # Sort and limit devices
        recent_devices = self.sort_manager.sort_items(list(self.wifi_devices.values()), limit=20)

        for device in recent_devices:
            # Format time columns
            first_seen_str, last_seen_str, total_time_str = DeviceTableFormatter.format_time_columns(device)
            
            # Format RSSI column
            rssi_display = DeviceTableFormatter.format_rssi_column(device.rssi)

            # Truncate long SSIDs and apply styling
            ssid_truncated = truncate_string(device.ssid, 20)
            if ssid_truncated == "Hidden":
                ssid_display = "[dim]Hidden[/dim]"
            elif ssid_truncated == "Client":
                ssid_display = "[dim]Client[/dim]"
            elif ssid_truncated.startswith("Client ("):
                ssid_display = f"[dim]{ssid_truncated}[/dim]"
            else:
                ssid_display = ssid_truncated

            # Format vendor column
            vendor_display = truncate_string(device.vendor, 15)
            if vendor_display == "Unknown":
                vendor_display = "[dim]Unknown[/dim]"
            elif vendor_display == "Randomized":
                vendor_display = "[yellow]Randomized[/yellow]"

            table.add_row(
                "AP" if device.device_type == "access_point" else "Client",
                Text(device.bssid),
                ssid_display,
                str(device.channel) if device.channel else "-",
                vendor_display,
                rssi_display,
                str(device.packet_count),
                first_seen_str,
                last_seen_str,
                total_time_str,
            )

        return table

    def _create_stats_panel(self) -> Panel:
        """Create WiFi statistics panel."""
        # Basic stats using common formatter
        basic_stats = StatsFormatter.format_basic_stats(self.stats, len(self.wifi_devices), "WiFi")

        # Count device types
        ap_count = sum(1 for d in self.wifi_devices.values() if d.device_type == "access_point")
        client_count = sum(1 for d in self.wifi_devices.values() if d.device_type == "client")

        # Count frame types
        beacon_count = sum(d.beacon_packets for d in self.wifi_devices.values())
        probe_count = sum(d.probe_packets for d in self.wifi_devices.values())
        data_count = sum(d.data_packets for d in self.wifi_devices.values())

        # WiFi-specific stats
        wifi_specific = f"""
📱 [bold]Device Types[/bold]
🏢 Access Points: {ap_count}
👤 Clients: {client_count}

📋 [bold]Frame Types[/bold]
🗼 Beacons: {beacon_count}
🔍 Probes: {probe_count}
📊 Data: {data_count}

📶 [bold]Current Channel: {self.current_channel}[/bold]
🌐 [bold]Enabled Bands:[/bold] {self._get_enabled_bands_display()}"""

        full_stats = basic_stats + wifi_specific
        return StatsFormatter.create_stats_panel(full_stats, "📈 WiFi Stats")

    def _get_enabled_bands_display(self) -> str:
        """Get a display string for enabled bands with support status."""
        supported_bands = self._get_supported_bands()
        bands = []

        # Show 2.4GHz status
        if self.enable_2_4ghz:
            if supported_bands["2.4ghz"]:
                bands.append("[green]2.4GHz[/green]")
            else:
                bands.append("[red]2.4GHz (unsupported)[/red]")
        else:
            bands.append("[dim]2.4GHz (disabled)[/dim]")

        # Show 5GHz status
        if self.enable_5ghz:
            if supported_bands["5ghz"]:
                bands.append("[green]5GHz[/green]")
            else:
                bands.append("[red]5GHz (unsupported)[/red]")
        else:
            bands.append("[dim]5GHz (disabled)[/dim]")

        # Show 6E status
        if self.enable_6e:
            if supported_bands["6e"]:
                bands.append("[green]6E[/green]")
            else:
                bands.append("[red]6E (unsupported)[/red]")
        else:
            bands.append("[dim]6E (disabled)[/dim]")

        return ", ".join(bands)

    def debug_band_detection(self) -> str:
        """Debug method to show band detection details."""
        import shutil
        import subprocess

        debug_info = []
        debug_info.append(f"Interface: {self.interface}")

        try:
            if shutil.which("iw"):
                # Get interface info
                result = subprocess.run(
                    ["iw", "dev", self.interface, "info"], capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    debug_info.append("Interface info:")
                    debug_info.append(result.stdout)
                else:
                    debug_info.append(f"Interface info failed: {result.stderr}")

                # Get PHY info
                result = subprocess.run(
                    ["iw", "phy", "info"], capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    debug_info.append("PHY info (first 50 lines):")
                    lines = result.stdout.split("\n")[:50]
                    debug_info.append("\n".join(lines))
                else:
                    debug_info.append(f"PHY info failed: {result.stderr}")
            else:
                debug_info.append("iw command not available")

        except Exception as e:
            debug_info.append(f"Debug error: {e}")

        detected_bands = self._get_supported_bands()
        debug_info.append(f"Detected bands: {detected_bands}")

        return "\n".join(debug_info)

    def _extract_channel_from_packet(self, packet) -> Optional[int]:
        """Extract channel number from WiFi packet supporting all bands."""
        channel = None

        # Method 1: Try RadioTap header frequency (most reliable for all bands)
        if hasattr(packet, "RadioTap") and hasattr(packet.RadioTap, "ChannelFrequency"):
            frequency = packet.RadioTap.ChannelFrequency
            channel = self._frequency_to_channel(frequency)
            if channel:
                return channel

        # Method 2: Try to extract from packet metadata
        if hasattr(packet, "dBm_AntSignal"):
            # Some drivers include frequency in the metadata
            if hasattr(packet, "Channel"):
                channel_value = packet.Channel
                # Check if this is actually a frequency (> 1000) rather than a channel number
                if channel_value > 1000:
                    # This is likely a frequency, convert it to channel
                    channel = self._frequency_to_channel(channel_value)
                    if channel:
                        return channel
                else:
                    # This is likely already a channel number
                    return channel_value
            if hasattr(packet, "ChannelFrequency"):
                frequency = packet.ChannelFrequency
                channel = self._frequency_to_channel(frequency)
                if channel:
                    return channel

        # Method 3: Parse Information Elements for channel info
        if packet.haslayer("Dot11Elt"):
            current_layer = packet["Dot11Elt"]
            while current_layer:
                if hasattr(current_layer, "ID"):
                    # DS Parameter Set IE (ID 3) - 2.4GHz only
                    if current_layer.ID == 3:
                        if hasattr(current_layer, "info") and len(current_layer.info) >= 1:
                            channel = current_layer.info[0]
                            if 1 <= channel <= 14:  # Valid 2.4GHz channel
                                return channel

                    # HT Operation IE (ID 61) - Contains primary channel for 5GHz
                    elif current_layer.ID == 61:
                        if hasattr(current_layer, "info") and len(current_layer.info) >= 1:
                            primary_channel = current_layer.info[0]
                            if primary_channel > 14:  # 5GHz channel
                                return primary_channel

                    # HE Operation IE (ID 255) - 6E band information
                    elif current_layer.ID == 255:
                        if hasattr(current_layer, "info") and len(current_layer.info) >= 3:
                            # HE Operation contains 6GHz channel information
                            # This is more complex but we can extract basic channel info
                            try:
                                # Simplified extraction - actual parsing is complex
                                if len(current_layer.info) >= 6:
                                    # Check if this is 6GHz operation
                                    he_oper_params = current_layer.info[0]
                                    if he_oper_params & 0x02:  # 6GHz operation present
                                        # Extract 6GHz primary channel (simplified)
                                        channel_info = current_layer.info[3:6]
                                        if len(channel_info) >= 1:
                                            channel = channel_info[0]
                                            # Return actual 6GHz channel number (1-233)
                                            if 1 <= channel <= 233:
                                                return channel
                            except:
                                pass

                # Move to next IE
                if hasattr(current_layer, "payload") and current_layer.payload:
                    next_layer = current_layer.payload
                    if hasattr(next_layer, "ID"):
                        current_layer = next_layer
                    else:
                        break
                else:
                    break

        # Fallback: Use current scanning channel if packet parsing failed
        if channel is None:
            return self.current_channel

        return channel

    def _frequency_to_channel(self, frequency: int) -> Optional[int]:
        """Convert frequency (MHz) to WiFi channel number."""
        if not frequency:
            return None

        # 2.4GHz band (2412-2484 MHz) → Channels 1-14
        if 2412 <= frequency <= 2484:
            if frequency == 2484:
                return 14
            else:
                return (frequency - 2412) // 5 + 1

        # 5GHz band → Standard WiFi channel numbers
        elif 5000 <= frequency <= 5895:
            # Use proper 5GHz channel mapping
            freq_to_channel_5ghz = {
                5170: 34,
                5180: 36,
                5190: 38,
                5200: 40,
                5210: 42,
                5220: 44,
                5230: 46,
                5240: 48,
                5250: 50,
                5260: 52,
                5270: 54,
                5280: 56,
                5290: 58,
                5300: 60,
                5310: 62,
                5320: 64,
                5500: 100,
                5510: 102,
                5520: 104,
                5530: 106,
                5540: 108,
                5550: 110,
                5560: 112,
                5570: 114,
                5580: 116,
                5590: 118,
                5600: 120,
                5610: 122,
                5620: 124,
                5630: 126,
                5640: 128,
                5660: 132,
                5670: 134,
                5680: 136,
                5690: 138,
                5700: 140,
                5710: 142,
                5720: 144,
                5745: 149,
                5755: 151,
                5765: 153,
                5775: 155,
                5785: 157,
                5795: 159,
                5805: 161,
                5815: 163,
                5825: 165,
            }

            # Find exact match first
            if frequency in freq_to_channel_5ghz:
                return freq_to_channel_5ghz[frequency]

            # Find closest frequency match (within 5 MHz)
            for freq, channel in freq_to_channel_5ghz.items():
                if abs(frequency - freq) <= 5:
                    return channel

        # 6E band (5925-7125 MHz) → Channels 1-233
        elif 5925 <= frequency <= 7125:
            # 6GHz band formula: frequency = 5950 + (channel * 5)
            # So: channel = (frequency - 5950) / 5
            if frequency >= 5955:  # First 6GHz channel is at 5955 MHz (channel 1)
                channel = (frequency - 5950) // 5
                # 6GHz channels are: 1, 5, 9, 13, 17, 21, ... (4n-3 pattern)
                # But for simplicity, we'll return the calculated channel if it's valid
                if 1 <= channel <= 233:
                    return channel

        return None

    def handle_keyboard_input(self, key: str) -> None:
        """Handle keyboard input for WiFi plugin."""
        key_mappings = {
            's': 'ssid',
            'r': 'rssi',
            'c': 'channel',
            'f': 'first_seen',
            'l': 'last_seen',
            'p': 'packets',
            't': 'total_time'
        }
        
        if key.lower() in key_mappings:
            self.sort_manager.handle_sort_key(key_mappings[key.lower()])

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
            "output_files": self._output_files,
        }
