"""
Common interface utilities for network interface validation and management.
"""

import os
import sys
from typing import List, Optional, Tuple

from loguru import logger
from rich.console import Console

from .common_ui import ErrorDisplayManager


class InterfaceValidator:
    """Validates and tests network interfaces."""

    @staticmethod
    def is_valid_hci_interface(interface_name: str) -> bool:
        """Check if interface is a valid HCI interface using hciconfig command."""
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

    @staticmethod
    def is_valid_wifi_interface(interface_name: str) -> bool:
        """Check if interface is a valid WiFi interface using ip command."""
        try:
            # Check if interface exists using ip link
            result = os.popen(f"ip link show {interface_name} 2>/dev/null").read()
            if not result or "does not exist" in result or "LOOPBACK" in result:
                return False

            # Check if interface name follows WiFi naming conventions
            # Common WiFi interface patterns: wlan*, wlp*, wlx*, ath*, ra*, etc.
            wifi_patterns = ["wlan", "wlp", "wlx", "ath", "ra", "wmaster", "mon"]
            return any(interface_name.startswith(pattern) for pattern in wifi_patterns)

        except Exception:
            return False

    @staticmethod
    def test_hci_interface(interface_name: str) -> bool:
        """Test if an HCI interface is available and working."""
        try:
            # First check if it's a valid HCI interface
            if not InterfaceValidator.is_valid_hci_interface(interface_name):
                return False

            # Extract interface number from string (e.g., "hci1" -> 1)
            from scapy.layers.bluetooth import BluetoothHCISocket

            interface_num = int(interface_name[3:])
            test_socket = BluetoothHCISocket(interface_num)
            test_socket.close()
            return True
        except (PermissionError, ValueError, Exception):
            return False

    @staticmethod
    def test_wifi_interface(interface_name: str) -> bool:
        """Test if a WiFi interface is available and working."""
        try:
            # First check if it's a valid WiFi interface
            if not InterfaceValidator.is_valid_wifi_interface(interface_name):
                return False

            # Check if interface is up or can be brought up
            result = os.popen(f"ip link show {interface_name} 2>/dev/null").read()
            return bool(result and "does not exist" not in result and "LOOPBACK" not in result)
        except Exception:
            return False


class InterfaceErrorHandler:
    """Handles interface-related errors with consistent messaging."""

    @staticmethod
    def exit_with_hci_error(interface: str, adapter_name: str = "Built-in Bluetooth") -> None:
        """Print HCI interface error message and exit."""
        console = Console()

        solutions = [
            ("Check available HCI interfaces", "hciconfig"),
            ("Check detailed interface status", "hciconfig -a"),
            (f"Enable the Bluetooth interface", f"sudo hciconfig {interface} up"),
            ("Check for Bluetooth hardware", "lsusb | grep -i bluetooth"),
        ]

        panel = ErrorDisplayManager.create_interface_error_panel("BLE", interface, "🔵", solutions)
        console.print(panel)
        sys.exit(1)

    @staticmethod
    def exit_with_wifi_error(interface: str) -> None:
        """Print WiFi interface error message and exit."""
        console = Console()

        solutions = [
            ("Check all network interfaces", "ip link show"),
            (f"Enable the interface", f"sudo ip link set {interface} up"),
            ("Check for WiFi hardware", "lspci | grep -i wireless"),
            ("Check USB WiFi adapters", "lsusb | grep -i wireless"),
            ("Install WiFi tools", "sudo apt install iw wireless-tools"),
        ]

        panel = ErrorDisplayManager.create_interface_error_panel("WiFi", interface, "📶", solutions)
        console.print(panel)
        sys.exit(1)


class RequirementsChecker:
    """Checks common plugin requirements."""

    @staticmethod
    def check_root_privileges() -> Tuple[bool, List[str]]:
        """Check if running with root privileges."""
        errors = []
        if os.geteuid() != 0:
            errors.append("Root privileges required for network operations")
        return len(errors) == 0, errors

    @staticmethod
    def check_scapy_bluetooth() -> Tuple[bool, List[str]]:
        """Check if Scapy Bluetooth support is available."""
        errors = []
        try:
            from scapy.layers.bluetooth import BluetoothHCISocket
        except ImportError:
            errors.append("Scapy Bluetooth support not available")
        return len(errors) == 0, errors
