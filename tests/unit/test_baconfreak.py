"""
Unit tests for baconfreak.py main function.
"""

import unittest
from unittest.mock import MagicMock, patch

from src.baconfreak import main
from src.exceptions import (
    BaconFreakError,
    BaconFreakInterfaceError,
    BaconFreakPermissionError,
)


class TestBaconFreakExceptions(unittest.TestCase):
    """Test custom exception classes."""

    def test_bacon_freak_error(self):
        """Test base BaconFreakError exception."""
        error = BaconFreakError("test error")
        self.assertEqual(str(error), "test error")
        self.assertIsInstance(error, Exception)

    def test_bacon_freak_permission_error(self):
        """Test BaconFreakPermissionError exception."""
        error = BaconFreakPermissionError("permission error")
        self.assertEqual(str(error), "permission error")
        self.assertIsInstance(error, BaconFreakError)

    def test_bacon_freak_interface_error(self):
        """Test BaconFreakInterfaceError exception."""
        error = BaconFreakInterfaceError("interface error")
        self.assertEqual(str(error), "interface error")
        self.assertIsInstance(error, BaconFreakError)


class TestBaconFreakMain(unittest.TestCase):
    """Test main function."""

    @patch("src.baconfreak.PluginManager")
    @patch("src.baconfreak.setup_logging")
    def test_main_basic(self, mock_setup_logging, mock_plugin_manager_class):
        """Test basic main function execution."""
        mock_manager = MagicMock()
        mock_plugin_manager_class.return_value = mock_manager
        mock_plugin = MagicMock()
        mock_manager.create_plugin.return_value = mock_plugin

        # Should not raise any exceptions
        main(protocol="ble", interface=1, quiet=True)

        mock_setup_logging.assert_called_once()
        mock_manager.create_plugin.assert_called_once()
        mock_manager.start_capture.assert_called_once()


if __name__ == "__main__":
    unittest.main()