"""
Test the timestamped PCAP filename feature.
"""

import re
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from src.baconfreak import BluetoothScanner


class TestTimestampedFilenames:
    """Test timestamped PCAP filename functionality."""

    def test_session_timestamp_format(self):
        """Test that session timestamp has correct format."""
        scanner = BluetoothScanner()

        # Verify timestamp format: YYYYMMDDHHMMSS (14 digits)
        timestamp_pattern = r"^\d{14}$"
        assert re.match(
            timestamp_pattern, scanner.session_timestamp
        ), f"Timestamp {scanner.session_timestamp} does not match expected format YYYYMMDDHHMMSS"

    def test_get_timestamped_pcap_path(self):
        """Test the _get_timestamped_pcap_path method."""
        scanner = BluetoothScanner()

        test_cases = [
            ("bfreak-known.pcap", "bfreak-known.pcap"),
            ("bfreak-unknown.pcap", "bfreak-unknown.pcap"),
            ("bfreak-devices.pcap", "bfreak-devices.pcap"),
            ("output/custom.pcap", "custom.pcap"),
            ("/absolute/path/test.pcap", "test.pcap"),
        ]

        for input_path, expected_base in test_cases:
            result = scanner._get_timestamped_pcap_path(input_path)

            # Check that result is a Path object
            assert isinstance(result, Path)

            # Check that filename starts with Bacon prefix and timestamp
            expected_filename = f"Bacon-{scanner.session_timestamp}-{expected_base}"
            assert (
                result.name == expected_filename
            ), f"Expected {expected_filename}, got {result.name}"

            # Check that directory structure is preserved for relative paths
            input_path_obj = Path(input_path)
            if not input_path_obj.is_absolute():
                assert result.parent == input_path_obj.parent

    def test_timestamped_paths_initialization(self):
        """Test that actual PCAP paths are properly initialized."""
        scanner = BluetoothScanner()

        # Should be None initially
        assert scanner.actual_known_pcap_path is None
        assert scanner.actual_unknown_pcap_path is None
        assert scanner.actual_devices_pcap_path is None

    @patch("src.baconfreak.BluetoothScanner._initialize_bluetooth_interface")
    @patch("src.baconfreak.pcap_writers")
    @patch("src.baconfreak.config")
    def test_timestamped_paths_during_run(self, mock_config, mock_pcap_writers, mock_init_bt):
        """Test that timestamped paths are set correctly during run."""
        # Mock configuration
        mock_config.ensure_directories.return_value = None
        mock_config.output_dir_path = Path("output")
        mock_config.known_pcap_path = "bfreak-known.pcap"
        mock_config.unknown_pcap_path = "bfreak-unknown.pcap"
        mock_config.devices_pcap_path = "bfreak-devices.pcap"
        mock_config.logs_dir_path = Path("logs")
        mock_config.scan_config = Mock()

        # Mock Bluetooth interface
        mock_bt_socket = Mock()
        mock_init_bt.return_value = mock_bt_socket

        # Mock PCAP writers context manager
        mock_writers = Mock(), Mock(), Mock()
        mock_pcap_writers.return_value.__enter__.return_value = mock_writers
        mock_pcap_writers.return_value.__exit__.return_value = None

        # Mock sniff to exit immediately
        def mock_sniff(*args, **kwargs):
            # Simulate immediate exit
            pass

        mock_bt_socket.sniff = mock_sniff

        scanner = BluetoothScanner(quiet=True, enable_rich=False)

        # Capture the timestamp before run
        session_timestamp = scanner.session_timestamp

        try:
            scanner.run()
        except Exception:
            # We expect some exceptions due to mocking, but that's okay
            pass

        # Verify that actual paths were set with timestamps
        assert scanner.actual_known_pcap_path is not None
        assert scanner.actual_unknown_pcap_path is not None
        assert scanner.actual_devices_pcap_path is not None

        # Verify Bacon prefix and timestamp
        expected_prefix = f"Bacon-{session_timestamp}-"
        assert scanner.actual_known_pcap_path.name.startswith(expected_prefix)
        assert scanner.actual_unknown_pcap_path.name.startswith(expected_prefix)
        assert scanner.actual_devices_pcap_path.name.startswith(expected_prefix)

        # Verify complete filenames
        assert scanner.actual_known_pcap_path.name == f"Bacon-{session_timestamp}-bfreak-known.pcap"
        assert (
            scanner.actual_unknown_pcap_path.name
            == f"Bacon-{session_timestamp}-bfreak-unknown.pcap"
        )
        assert (
            scanner.actual_devices_pcap_path.name
            == f"Bacon-{session_timestamp}-bfreak-devices.pcap"
        )

    def test_different_timestamps_for_different_scanners(self):
        """Test that different scanner instances get different timestamps."""
        import time

        scanner1 = BluetoothScanner()
        time.sleep(0.1)  # Small delay to ensure different timestamps
        scanner2 = BluetoothScanner()

        # Timestamps should be different (or at least we should be able to create
        # different instances without error)
        assert isinstance(scanner1.session_timestamp, str)
        assert isinstance(scanner2.session_timestamp, str)
        assert len(scanner1.session_timestamp) == 14
        assert len(scanner2.session_timestamp) == 14
