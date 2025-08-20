"""
Test that scapy verbose output is suppressed during HCI operations.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock

from src.plugins.ble.plugin import BLEPlugin
from rich.console import Console


class TestVerboseOutputSuppression:
    """Test that scapy verbose output is properly suppressed."""
    
    def test_ble_plugin_initialization_verbose_suppressed(self):
        """Test that BLE plugin initialization suppresses verbose output."""
        config = {
            "interface": "hci1",
            "scan_timeout": 0,
            "min_rssi": -100,
            "filter_duplicates": False
        }
        
        plugin = BLEPlugin(config, Console())
        
        # Mock the Bluetooth socket and its sr method
        mock_socket = Mock()
        mock_sr_response = ([Mock()], [])  # (answered, unanswered)
        mock_socket.sr.return_value = mock_sr_response
        
        with patch('src.plugins.ble.plugin.BluetoothHCISocket', return_value=mock_socket):
            with patch('src.plugins.ble.plugin.CompanyIdentifiers'):
                with patch('src.plugins.ble.plugin.DeviceDetector'):
                    # Initialize the plugin
                    plugin.initialize_capture()
                    
                    # Verify sr was called with verbose=False
                    mock_socket.sr.assert_called_once()
                    call_args = mock_socket.sr.call_args
                    
                    # Check that verbose=False was passed
                    assert 'verbose' in call_args.kwargs
                    assert call_args.kwargs['verbose'] is False
    
    def test_ble_plugin_stop_capture_verbose_suppressed(self):
        """Test that BLE plugin stop_capture suppresses verbose output."""
        config = {
            "interface": "hci1",
            "scan_timeout": 0,
            "min_rssi": -100,
            "filter_duplicates": False
        }
        
        plugin = BLEPlugin(config, Console())
        
        # Mock the Bluetooth socket 
        mock_socket = Mock()
        mock_socket.sr.return_value = ([Mock()], [])
        mock_socket.close = Mock()
        
        # Set the socket on the plugin
        plugin.bt_socket = mock_socket
        
        # Call stop_capture
        plugin.stop_capture()
        
        # Verify sr was called with verbose=False during shutdown
        mock_socket.sr.assert_called_once()
        call_args = mock_socket.sr.call_args
        
        # Check that verbose=False was passed
        assert 'verbose' in call_args.kwargs
        assert call_args.kwargs['verbose'] is False
    
    def test_ble_plugin_stop_capture_handles_sr_errors(self):
        """Test that BLE plugin handles sr errors gracefully during stop."""
        config = {
            "interface": "hci1",
            "scan_timeout": 0,
            "min_rssi": -100,
            "filter_duplicates": False
        }
        
        plugin = BLEPlugin(config, Console())
        
        # Mock the Bluetooth socket to raise an exception on sr but succeed on close
        mock_socket = Mock()
        mock_socket.sr.side_effect = Exception("HCI error")
        mock_socket.close = Mock()
        
        # Set the socket on the plugin
        plugin.bt_socket = mock_socket
        
        # Call stop_capture - should not raise an exception
        plugin.stop_capture()
        
        # Verify sr was called (but failed)
        mock_socket.sr.assert_called_once()
        
        # Verify close was still called despite sr error (improved behavior)
        mock_socket.close.assert_called_once()
    
    @patch('src.baconfreak.BluetoothHCISocket')
    def test_legacy_baconfreak_verbose_suppressed(self, mock_socket_class):
        """Test that legacy baconfreak.py also suppresses verbose output."""
        # This test would require more setup for the legacy code
        # For now, we'll just verify the pattern is consistent
        
        # Read the baconfreak.py file to check for verbose=False
        with open('src/baconfreak.py', 'r') as f:
            content = f.read()
        
        # Verify that sr calls include verbose=False
        assert 'sr(scan_command, verbose=False)' in content
    
    def test_all_sr_calls_have_verbose_false(self):
        """Test that all .sr() calls in the codebase include verbose=False."""
        import os
        import re
        
        # Pattern to find .sr( calls
        sr_pattern = r'\.sr\([^)]*\)'
        
        # Files to check
        files_to_check = [
            'src/baconfreak.py',
            'src/plugins/ble/plugin.py'
        ]
        
        for file_path in files_to_check:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Find all .sr( calls
                sr_calls = re.findall(sr_pattern, content)
                
                for call in sr_calls:
                    # Each sr call should include verbose=False
                    assert 'verbose=False' in call, f"sr call without verbose=False in {file_path}: {call}"