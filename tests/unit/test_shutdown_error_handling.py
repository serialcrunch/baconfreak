"""
Test improved shutdown error handling for "Bad file descriptor" errors.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock

from src.plugins.ble.plugin import BLEPlugin
from rich.console import Console


class TestShutdownErrorHandling:
    """Test improved error handling during shutdown."""
    
    def test_ble_plugin_handles_bad_file_descriptor(self):
        """Test that BLE plugin gracefully handles OSError during shutdown."""
        config = {
            "interface": "hci1",
            "scan_timeout": 0,
            "min_rssi": -100,
            "filter_duplicates": False
        }
        
        plugin = BLEPlugin(config, Console())
        
        # Mock the Bluetooth socket with a bad file descriptor error
        mock_socket = Mock()
        mock_socket.ins.fileno.side_effect = OSError("Bad file descriptor")
        
        # Set the socket on the plugin
        plugin.bt_socket = mock_socket
        
        # Call stop_capture - should not raise an exception
        plugin.stop_capture()
        
        # Verify fileno was called (which triggered the error)
        mock_socket.ins.fileno.assert_called_once()
    
    def test_ble_plugin_handles_sr_oserror(self):
        """Test that BLE plugin handles OSError during sr() call."""
        config = {
            "interface": "hci1",
            "scan_timeout": 0,
            "min_rssi": -100,
            "filter_duplicates": False
        }
        
        plugin = BLEPlugin(config, Console())
        
        # Mock socket that passes fileno check but fails on sr
        mock_socket = Mock()
        mock_socket.ins.fileno.return_value = 5  # Valid file descriptor
        mock_socket.sr.side_effect = OSError("Bad file descriptor")
        mock_socket.close = Mock()
        
        plugin.bt_socket = mock_socket
        
        # Should not raise exception
        plugin.stop_capture()
        
        # Verify sr was attempted
        mock_socket.sr.assert_called_once()
        # Verify socket was still closed
        mock_socket.close.assert_called_once()
    
    def test_ble_plugin_skips_invalid_socket(self):
        """Test that BLE plugin skips disable command for invalid socket."""
        config = {
            "interface": "hci1",
            "scan_timeout": 0,
            "min_rssi": -100,
            "filter_duplicates": False
        }
        
        plugin = BLEPlugin(config, Console())
        
        # Mock socket without ins attribute (invalid socket)
        mock_socket = Mock()
        del mock_socket.ins  # Remove ins attribute
        mock_socket.close = Mock()
        
        plugin.bt_socket = mock_socket
        
        # Should not raise exception and should skip sr call
        plugin.stop_capture()
        
        # Verify sr was not called (since socket was invalid)
        assert not hasattr(mock_socket, 'sr') or not mock_socket.sr.called
        # Verify socket was still closed
        mock_socket.close.assert_called_once()
    
    @patch('logging.getLogger')
    def test_ble_plugin_suppresses_scapy_logging(self, mock_get_logger):
        """Test that scapy logging is temporarily suppressed during shutdown."""
        config = {
            "interface": "hci1",
            "scan_timeout": 0,
            "min_rssi": -100,
            "filter_duplicates": False
        }
        
        plugin = BLEPlugin(config, Console())
        
        # Mock scapy logger
        mock_scapy_logger = Mock()
        mock_scapy_logger.level = 20  # INFO level
        mock_get_logger.return_value = mock_scapy_logger
        
        # Mock valid socket
        mock_socket = Mock()
        mock_socket.ins.fileno.return_value = 5
        mock_socket.sr.return_value = ([], [])  # Successful response
        mock_socket.close = Mock()
        
        plugin.bt_socket = mock_socket
        
        # Call stop_capture
        plugin.stop_capture()
        
        # Verify scapy logger level was temporarily changed
        calls = mock_scapy_logger.setLevel.call_args_list
        assert len(calls) >= 2  # Should be called to suppress and restore
        
        # First call should set to CRITICAL (50)
        first_call_level = calls[0][0][0]
        assert first_call_level == 50  # logging.CRITICAL
        
        # Last call should restore original level (20)
        last_call_level = calls[-1][0][0]
        assert last_call_level == 20  # Original INFO level
    
    def test_ble_plugin_handles_any_exception_gracefully(self):
        """Test that any unexpected exception during shutdown is handled."""
        config = {
            "interface": "hci1",
            "scan_timeout": 0,
            "min_rssi": -100,
            "filter_duplicates": False
        }
        
        plugin = BLEPlugin(config, Console())
        
        # Mock socket that raises unexpected exception
        mock_socket = Mock()
        mock_socket.ins.fileno.side_effect = RuntimeError("Unexpected error")
        mock_socket.close = Mock()
        
        plugin.bt_socket = mock_socket
        
        # Should not raise exception even for unexpected errors
        plugin.stop_capture()
        
        # Verify socket was still closed despite error
        mock_socket.close.assert_called_once()
    
    def test_socket_validity_check_methods(self):
        """Test the different ways we check socket validity."""
        config = {
            "interface": "hci1",
            "scan_timeout": 0,
            "min_rssi": -100,
            "filter_duplicates": False
        }
        
        plugin = BLEPlugin(config, Console())
        
        # Test case 1: Socket with no ins attribute
        mock_socket1 = Mock()
        del mock_socket1.ins
        plugin.bt_socket = mock_socket1
        # Should handle gracefully - tested in other methods
        
        # Test case 2: Socket with ins but no fileno
        mock_socket2 = Mock()
        mock_socket2.ins = Mock()
        del mock_socket2.ins.fileno
        plugin.bt_socket = mock_socket2
        # Should handle gracefully
        
        # Test case 3: Valid socket
        mock_socket3 = Mock()
        mock_socket3.ins.fileno.return_value = 5
        plugin.bt_socket = mock_socket3
        # Should work normally
        
        # All should complete without exceptions
        for socket in [mock_socket1, mock_socket2, mock_socket3]:
            plugin.bt_socket = socket
            plugin.stop_capture()  # Should not raise