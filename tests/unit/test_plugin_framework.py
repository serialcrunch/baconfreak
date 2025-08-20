"""
Unit tests for the plugin framework.
"""

import unittest
from unittest.mock import Mock, patch
from pathlib import Path

from src.plugins import plugin_registry, PluginManager, TabbedPluginManager
from src.plugins.ble import BLEPlugin
from src.plugins.wifi import WiFiPlugin
from src.plugins.base import PluginInfo, PluginError


class TestPluginRegistry(unittest.TestCase):
    """Test plugin registry functionality."""
    
    def test_plugin_registry_has_both_plugins(self):
        """Test that both BLE and WiFi plugins are registered."""
        protocols = plugin_registry.list_protocols()
        self.assertIn("ble", protocols)
        self.assertIn("wifi", protocols)
    
    def test_get_ble_plugin_info(self):
        """Test getting BLE plugin information."""
        info = plugin_registry.get_plugin_info("ble")
        self.assertIsInstance(info, PluginInfo)
        self.assertEqual(info.protocol, "ble")
        self.assertEqual(info.name, "BLE Scanner")
        self.assertTrue(info.requires_root)
    
    def test_create_ble_plugin(self):
        """Test creating BLE plugin instance."""
        config = {
            "interface": "hci1",
            "scan_timeout": 0,
            "filter_duplicates": False,
            "min_rssi": -100
        }
        
        plugin = plugin_registry.create_plugin("ble", config)
        self.assertIsInstance(plugin, BLEPlugin)
        self.assertEqual(plugin.interface, "hci1")
    
    def test_unknown_protocol(self):
        """Test handling unknown protocol."""
        plugin = plugin_registry.create_plugin("unknown", {})
        self.assertIsNone(plugin)


class TestBLEPlugin(unittest.TestCase):
    """Test BLE plugin functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "interface": "hci1",
            "scan_timeout": 10,
            "filter_duplicates": True,
            "min_rssi": -80
        }
        self.plugin = BLEPlugin(self.config)
    
    def test_plugin_info(self):
        """Test plugin info."""
        info = self.plugin.info
        self.assertEqual(info.protocol, "ble")
        self.assertEqual(info.name, "BLE Scanner")
        self.assertTrue(info.requires_root)
        self.assertIn("linux", info.supported_platforms)
    
    @patch('src.plugins.ble.plugin.BLEPlugin._is_valid_hci_interface')
    def test_config_validation(self, mock_is_valid):
        """Test configuration validation."""
        mock_is_valid.return_value = True
        valid, errors = self.plugin.validate_config()
        self.assertTrue(valid, f"Config validation failed: {errors}")
        self.assertEqual(len(errors), 0)
    
    @patch('src.plugins.ble.plugin.BLEPlugin._is_valid_hci_interface')
    def test_invalid_config(self, mock_is_valid):
        """Test invalid configuration."""
        mock_is_valid.return_value = False  # Interface is invalid
        bad_plugin = BLEPlugin({
            "interface": "invalid_interface",  # Invalid
            "scan_timeout": -5,  # Invalid
            "min_rssi": 200  # Invalid
        })
        
        valid, errors = bad_plugin.validate_config()
        self.assertFalse(valid)
        self.assertGreater(len(errors), 0)
    
    def test_default_output_files(self):
        """Test default output file generation."""
        output_dir = Path("/tmp/test")
        files = self.plugin.get_default_output_files(output_dir)
        
        self.assertIn("known_devices", files)
        self.assertIn("unknown_devices", files)
        self.assertIn("special_devices", files)
        
        # Check that files have correct naming pattern
        for file_path in files.values():
            self.assertTrue(str(file_path).startswith(str(output_dir)))
            self.assertIn("BLE-", str(file_path))
    
    def test_timestamped_filename(self):
        """Test timestamped filename generation."""
        filename = self.plugin.get_timestamped_filename("test.pcap")
        self.assertIn("BLE-", filename)
        self.assertTrue(filename.endswith(".pcap"))
    
    def test_statistics(self):
        """Test getting plugin statistics."""
        stats = self.plugin.get_statistics()
        
        self.assertEqual(stats["protocol"], "BLE")
        self.assertIn("interface", stats)
        self.assertIn("devices", stats)
        self.assertIn("packets", stats)


class TestPluginManager(unittest.TestCase):
    """Test plugin manager functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.manager = PluginManager()
    
    def test_list_available_plugins(self):
        """Test listing available plugins."""
        plugins = self.manager.list_available_plugins()
        self.assertIn("ble", plugins)
        self.assertIsInstance(plugins["ble"], PluginInfo)
    
    @patch('os.geteuid')
    @patch('scapy.layers.bluetooth.BluetoothHCISocket')
    def test_create_valid_plugin(self, mock_socket, mock_geteuid):
        """Test creating valid plugin."""
        # Mock running as root and successful socket creation
        mock_geteuid.return_value = 0
        mock_socket_instance = Mock()
        mock_socket.return_value = mock_socket_instance
        
        config = {
            "interface": "hci1",
            "scan_timeout": 0,
            "filter_duplicates": False,
            "min_rssi": -100
        }
        
        plugin = self.manager.create_plugin("ble", config)
        self.assertIsInstance(plugin, BLEPlugin)
    
    def test_create_invalid_protocol(self):
        """Test creating plugin with invalid protocol."""
        with self.assertRaises(PluginError):
            self.manager.create_plugin("invalid", {})
    
    def test_create_plugin_invalid_config(self):
        """Test creating plugin with invalid configuration."""
        bad_config = {
            "interface": -1,  # Invalid
            "min_rssi": 300   # Invalid
        }
        
        with self.assertRaises(PluginError):
            self.manager.create_plugin("ble", bad_config)
    
    @patch('os.geteuid')
    def test_create_plugin_requirements_not_met(self, mock_geteuid):
        """Test creating plugin when requirements not met."""
        # Simulate not running as root
        mock_geteuid.return_value = 1000
        
        config = {
            "interface": "hci1",
            "scan_timeout": 0,
            "filter_duplicates": False,
            "min_rssi": -100
        }
        
        with self.assertRaises(PluginError):
            self.manager.create_plugin("ble", config)
    
    def test_stop_without_active_plugin(self):
        """Test stopping manager without active plugin."""
        # Should not raise exception
        self.manager.stop()
        self.assertIsNone(self.manager.active_plugin)


class TestWiFiPlugin(unittest.TestCase):
    """Test WiFi plugin functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "interface": "wlan0",
            "scan_timeout": 10,
            "channels": [1, 6, 11],
            "channel_hop": True,
            "min_rssi": -80
        }
        self.plugin = WiFiPlugin(self.config)
    
    def test_plugin_info(self):
        """Test WiFi plugin info."""
        info = self.plugin.info
        self.assertEqual(info.protocol, "wifi")
        self.assertEqual(info.name, "WiFi Scanner")
        self.assertTrue(info.requires_root)
        self.assertIn("linux", info.supported_platforms)
    
    @patch('src.plugins.wifi.plugin.WiFiPlugin._is_valid_wifi_interface')
    def test_config_validation(self, mock_is_valid):
        """Test WiFi configuration validation."""
        mock_is_valid.return_value = True
        valid, errors = self.plugin.validate_config()
        self.assertTrue(valid, f"Config validation failed: {errors}")
        self.assertEqual(len(errors), 0)
    
    def test_invalid_wifi_config(self):
        """Test invalid WiFi configuration."""
        bad_plugin = WiFiPlugin({
            "interface": "",  # Invalid
            "scan_timeout": -5,  # Invalid
            "channels": ["invalid"],  # Invalid
            "min_rssi": 200  # Invalid
        })
        
        valid, errors = bad_plugin.validate_config()
        self.assertFalse(valid)
        self.assertGreater(len(errors), 0)
    
    def test_wifi_output_files(self):
        """Test WiFi output file generation."""
        output_dir = Path("/tmp/test")
        files = self.plugin.get_default_output_files(output_dir)
        
        self.assertIn("beacon_frames", files)
        self.assertIn("probe_requests", files)
        self.assertIn("data_frames", files)
        self.assertIn("all_frames", files)
        
        # Check that files have correct naming pattern
        for file_path in files.values():
            self.assertTrue(str(file_path).startswith(str(output_dir)))
            self.assertIn("WIFI-", str(file_path))
    
    def test_wifi_statistics(self):
        """Test getting WiFi plugin statistics."""
        stats = self.plugin.get_statistics()
        
        self.assertEqual(stats["protocol"], "WiFi")
        self.assertIn("interface", stats)
        self.assertIn("devices", stats)
        self.assertIn("access_points", stats)
        self.assertIn("clients", stats)


class TestTabbedPluginManager(unittest.TestCase):
    """Test tabbed plugin manager functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.manager = TabbedPluginManager()
    
    def test_empty_manager(self):
        """Test empty tabbed manager."""
        self.assertEqual(len(self.manager.active_plugins), 0)
        self.assertEqual(len(self.manager.tab_names), 0)
        self.assertIsNone(self.manager.get_current_plugin())
    
    @patch('os.geteuid')
    @patch('scapy.layers.bluetooth.BluetoothHCISocket')
    @patch('src.plugins.ble.plugin.BLEPlugin._is_valid_hci_interface')
    def test_add_ble_plugin(self, mock_is_valid, mock_socket, mock_geteuid):
        """Test adding BLE plugin to tabbed manager."""
        # Mock running as root and successful socket creation
        mock_geteuid.return_value = 0
        mock_is_valid.return_value = True
        mock_socket_instance = Mock()
        mock_socket.return_value = mock_socket_instance
        
        config = {
            "interface": "hci1",
            "scan_timeout": 0,
            "filter_duplicates": False,
            "min_rssi": -100
        }
        
        plugin = self.manager.add_plugin("ble", config)
        self.assertIsInstance(plugin, BLEPlugin)
        self.assertIn("ble", self.manager.active_plugins)
        self.assertIn("BLE", self.manager.tab_names)
    
    @patch('os.geteuid')
    @patch('scapy.layers.bluetooth.BluetoothHCISocket')
    @patch('os.popen')
    @patch('src.plugins.wifi.plugin.WiFiPlugin._is_valid_wifi_interface')
    @patch('src.plugins.ble.plugin.BLEPlugin._is_valid_hci_interface')
    def test_add_multiple_plugins(self, mock_ble_valid, mock_wifi_valid, mock_popen, mock_socket, mock_geteuid):
        """Test adding multiple plugins to tabbed manager."""
        # Mock running as root
        mock_geteuid.return_value = 0
        mock_ble_valid.return_value = True
        mock_wifi_valid.return_value = True
        mock_socket_instance = Mock()
        mock_socket.return_value = mock_socket_instance
        
        # Mock WiFi interface check
        mock_popen.return_value.read.return_value = "wlan0: interface exists"
        
        # Add BLE plugin
        ble_config = {
            "interface": "hci1",
            "scan_timeout": 0,
            "filter_duplicates": False,
            "min_rssi": -100
        }
        ble_plugin = self.manager.add_plugin("ble", ble_config)
        
        # Add WiFi plugin
        wifi_config = {
            "interface": "wlan0",
            "scan_timeout": 0,
            "channels": [1, 6, 11],
            "channel_hop": True,
            "min_rssi": -100
        }
        wifi_plugin = self.manager.add_plugin("wifi", wifi_config)
        
        self.assertEqual(len(self.manager.active_plugins), 2)
        self.assertEqual(len(self.manager.tab_names), 2)
        self.assertIn("BLE", self.manager.tab_names)
        self.assertIn("WIFI", self.manager.tab_names)
    
    def test_tab_switching(self):
        """Test tab switching functionality."""
        # Add mock plugins to test switching
        self.manager.tab_names = ["BLE", "WIFI"]
        self.manager.current_tab = 0
        
        # Switch to next tab
        self.manager.switch_tab(1)
        self.assertEqual(self.manager.current_tab, 1)
        
        # Switch to next tab (should wrap around)
        self.manager.switch_tab(1)
        self.assertEqual(self.manager.current_tab, 0)
        
        # Switch to previous tab
        self.manager.switch_tab(-1)
        self.assertEqual(self.manager.current_tab, 1)
    
    def test_stop_without_active_plugins(self):
        """Test stopping tabbed manager without active plugins."""
        # Should not raise exception
        self.manager.stop()
        self.assertEqual(len(self.manager.active_plugins), 0)


if __name__ == "__main__":
    unittest.main()