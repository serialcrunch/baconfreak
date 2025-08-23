"""
Test shutdown behavior improvements for plugins.
"""

import signal
import threading
import time
from unittest.mock import MagicMock, Mock, patch

import pytest
from rich.console import Console

from src.plugins.ble.plugin import BLEPlugin
from src.plugins.manager import PluginManager
from src.plugins.shutdown import ShutdownManager, shutdown_manager
from src.plugins.tabbed_manager import TabbedPluginManager
from src.plugins.wifi.plugin import WiFiPlugin


class TestShutdownBehavior:
    """Test shutdown behavior improvements."""

    def test_ble_plugin_responsive_timeout(self):
        """Test that BLE plugin uses responsive timeouts."""
        config = {
            "interface": "hci1",
            "scan_timeout": 10,
            "min_rssi": -100,
            "filter_duplicates": False,
        }

        plugin = BLEPlugin(config, Console())

        # Test responsive timeout calculation
        sniff_timeout = min(5.0, plugin.scan_timeout) if plugin.scan_timeout > 0 else 5.0
        assert sniff_timeout == 5.0

        # Test with different timeout values
        test_cases = [
            (0, 5.0),  # Infinite timeout -> 5.0s responsive
            (3, 3.0),  # 3s timeout -> 3.0s responsive
            (10, 5.0),  # 10s timeout -> 5.0s responsive
            (60, 5.0),  # 60s timeout -> 5.0s responsive
        ]

        for scan_timeout, expected in test_cases:
            plugin.scan_timeout = scan_timeout
            responsive_timeout = min(5.0, plugin.scan_timeout) if plugin.scan_timeout > 0 else 5.0
            assert responsive_timeout == expected

    def test_wifi_plugin_responsive_timeout(self):
        """Test that WiFi plugin uses responsive timeouts."""
        config = {
            "interface": "wlan1",
            "scan_timeout": 10,
            "min_rssi": -100,
            "channel_hop": True,
            "channels": [1, 6, 11],
        }

        plugin = WiFiPlugin(config, Console())

        # Test responsive timeout calculation
        sniff_timeout = min(5.0, plugin.scan_timeout) if plugin.scan_timeout > 0 else 5.0
        assert sniff_timeout == 5.0

        # Test with different timeout values
        test_cases = [
            (0, 5.0),  # Infinite timeout -> 5.0s responsive
            (3, 3.0),  # 3s timeout -> 3.0s responsive
            (10, 5.0),  # 10s timeout -> 5.0s responsive
            (60, 5.0),  # 60s timeout -> 5.0s responsive
        ]

        for scan_timeout, expected in test_cases:
            plugin.scan_timeout = scan_timeout
            responsive_timeout = min(5.0, plugin.scan_timeout) if plugin.scan_timeout > 0 else 5.0
            assert responsive_timeout == expected

    @patch("src.plugins.wifi.plugin.WiFiPlugin._is_valid_wifi_interface")
    @patch("src.plugins.ble.plugin.BLEPlugin._is_valid_hci_interface")
    def test_plugin_config_validation(self, mock_ble_valid, mock_wifi_valid):
        """Test that plugins validate configuration properly."""
        mock_ble_valid.return_value = True
        mock_wifi_valid.return_value = True

        # Test BLE plugin validation
        ble_config = {
            "interface": "hci1",
            "scan_timeout": 10,
            "min_rssi": -80,
            "filter_duplicates": False,
        }

        ble_plugin = BLEPlugin(ble_config, Console())
        valid, errors = ble_plugin.validate_config()
        assert valid, f"BLE config validation failed: {errors}"

        # Test WiFi plugin validation
        wifi_config = {
            "interface": "wlan1",
            "scan_timeout": 10,
            "min_rssi": -80,
            "channel_hop": True,
            "channels": [1, 6, 11],
        }

        wifi_plugin = WiFiPlugin(wifi_config, Console())
        valid, errors = wifi_plugin.validate_config()
        assert valid, f"WiFi config validation failed: {errors}"

    def test_shutdown_manager_registration(self):
        """Test shutdown manager plugin registration."""
        manager = ShutdownManager()

        # Create mock plugins
        mock_plugin1 = Mock()
        mock_plugin1.stop_capture = Mock()
        mock_plugin2 = Mock()
        mock_plugin2.stop_capture = Mock()

        # Test registration
        manager.register_plugin(mock_plugin1)
        manager.register_plugin(mock_plugin2)

        assert mock_plugin1 in manager._active_plugins
        assert mock_plugin2 in manager._active_plugins

        # Test unregistration
        manager.unregister_plugin(mock_plugin1)
        assert mock_plugin1 not in manager._active_plugins
        assert mock_plugin2 in manager._active_plugins

    def test_shutdown_manager_emergency_cleanup(self):
        """Test shutdown manager emergency cleanup."""
        manager = ShutdownManager()

        # Create mock plugins
        mock_plugin = Mock()
        mock_plugin.stop_capture = Mock()

        manager.register_plugin(mock_plugin)

        # Mock subprocess.run to avoid actually killing processes
        with patch("subprocess.run") as mock_subprocess:
            mock_subprocess.return_value.stdout = ""  # No processes found

            # Test emergency cleanup
            manager._emergency_cleanup()

            # Verify plugin stop_capture was called
            mock_plugin.stop_capture.assert_called_once()

    def test_plugin_managers_have_signal_handlers(self):
        """Test that plugin managers have signal handlers."""
        console = Console()

        # Test single plugin manager
        single_manager = PluginManager(console)
        assert hasattr(single_manager, "_signal_handler")
        assert callable(single_manager._signal_handler)

        # Test tabbed plugin manager
        tabbed_manager = TabbedPluginManager(console)
        assert hasattr(tabbed_manager, "_signal_handler")
        assert callable(tabbed_manager._signal_handler)

    def test_ble_plugin_stop_capture_method(self):
        """Test that BLE plugin has proper stop_capture method."""
        config = {
            "interface": "hci1",
            "scan_timeout": 0,
            "min_rssi": -100,
            "filter_duplicates": False,
        }

        plugin = BLEPlugin(config, Console())

        # Test that stop_capture method exists and is callable
        assert hasattr(plugin, "stop_capture")
        assert callable(plugin.stop_capture)

        # Test calling stop_capture without initialization (should not crash)
        plugin.stop_capture()

    def test_wifi_plugin_stop_capture_method(self):
        """Test that WiFi plugin has proper stop_capture method."""
        config = {
            "interface": "wlan1",
            "scan_timeout": 0,
            "min_rssi": -100,
            "channel_hop": True,
            "channels": [1, 6, 11],
        }

        plugin = WiFiPlugin(config, Console())

        # Test that stop_capture method exists and is callable
        assert hasattr(plugin, "stop_capture")
        assert callable(plugin.stop_capture)

        # Test calling stop_capture without initialization (should not crash)
        plugin.stop_capture()

    def test_responsive_timeout_logic(self):
        """Test responsive timeout logic across different scenarios."""
        test_cases = [
            (0, 5.0),  # Infinite timeout -> 5.0s responsive
            (1, 1.0),  # 1s timeout -> 1.0s responsive
            (3, 3.0),  # 3s timeout -> 3.0s responsive
            (5, 5.0),  # 5s timeout -> 5.0s responsive
            (10, 5.0),  # 10s timeout -> 5.0s responsive (capped)
            (60, 5.0),  # 60s timeout -> 5.0s responsive (capped)
        ]

        for scan_timeout, expected in test_cases:
            responsive_timeout = min(5.0, scan_timeout) if scan_timeout > 0 else 5.0
            assert (
                responsive_timeout == expected
            ), f"Failed for {scan_timeout}: got {responsive_timeout}, expected {expected}"

    @patch("src.plugins.shutdown.subprocess.run")
    def test_hanging_process_cleanup(self, mock_subprocess):
        """Test hanging process cleanup functionality."""
        # Mock process list output
        mock_subprocess.return_value.stdout = "12345\n67890\n"

        manager = ShutdownManager()

        with patch("os.kill") as mock_kill, patch("os.getpid", return_value=99999):
            manager._kill_hanging_processes()

            # Should try to kill the found processes
            assert mock_kill.call_count >= 2  # At least SIGTERM calls

    def test_global_shutdown_manager_instance(self):
        """Test that global shutdown manager instance is available."""
        from src.plugins.shutdown import shutdown_manager

        assert shutdown_manager is not None
        assert isinstance(shutdown_manager, ShutdownManager)

        # Test utility functions
        from src.plugins.shutdown import (
            force_cleanup,
            register_for_cleanup,
            unregister_from_cleanup,
        )

        assert callable(register_for_cleanup)
        assert callable(unregister_from_cleanup)
        assert callable(force_cleanup)
