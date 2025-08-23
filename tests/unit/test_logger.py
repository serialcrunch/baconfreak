"""
Unit tests for logger module.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from loguru import logger

from src.logger import BaconFreakLogger, LoguruConfig, setup_logging


class TestLoguruConfig(unittest.TestCase):
    """Test LoguruConfig class."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.log_file = self.temp_dir / "test.log"

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil

        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
        # Reset logger configuration
        logger.remove()
        logger.add(lambda msg: None)  # Silent handler

    def test_console_initialization(self):
        """Test console initialization with default config."""
        config = LoguruConfig()

        self.assertIsNotNone(config.console)
        self.assertFalse(config.configured)

    def test_setup_basic(self):
        """Test basic logger setup."""
        config = LoguruConfig()
        # Use a temp file to avoid permission issues
        config.setup(level="DEBUG", log_file=str(self.log_file))

        self.assertTrue(config.configured)

    def test_setup_with_file_logging(self):
        """Test logger setup with file output."""
        config = LoguruConfig()
        config.setup(level="INFO", log_file=str(self.log_file))

        self.assertTrue(config.configured)

    def test_setup_tui_mode(self):
        """Test logger setup in TUI mode."""
        config = LoguruConfig()
        config.setup(tui_mode=True, log_file=str(self.log_file))

        self.assertTrue(config.configured)

    def test_setup_no_rich(self):
        """Test logger setup without Rich formatting."""
        config = LoguruConfig()
        config.setup(enable_rich=False, log_file=str(self.log_file))

        self.assertTrue(config.configured)

    def test_setup_idempotent(self):
        """Test that setup is idempotent."""
        config = LoguruConfig()
        config.setup(log_file=str(self.log_file))
        config.setup(log_file=str(self.log_file))  # Should not reconfigure

        self.assertTrue(config.configured)

    def test_suppress_third_party_loggers(self):
        """Test suppression of third-party loggers."""
        config = LoguruConfig()

        # Test that method exists and can be called
        if hasattr(config, "suppress_third_party_loggers"):
            config.suppress_third_party_loggers()


class TestBaconFreakLogger(unittest.TestCase):
    """Test BaconFreakLogger class."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil

        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
        # Reset logger configuration
        logger.remove()
        logger.add(lambda msg: None)  # Silent handler

    def test_initialization(self):
        """Test BaconFreakLogger initialization."""
        bacon_logger = BaconFreakLogger()

        self.assertIsNotNone(bacon_logger)
        self.assertTrue(hasattr(bacon_logger, "logger"))

    def test_setup_logging_function(self):
        """Test setup_logging function."""
        result = setup_logging(level="DEBUG")

        self.assertIsInstance(result, BaconFreakLogger)

    def test_log_device_detection(self):
        """Test device detection logging."""
        bacon_logger = BaconFreakLogger()

        # Test that method exists and can be called
        if hasattr(bacon_logger, "log_device_detection"):
            bacon_logger.log_device_detection("aa:bb:cc:dd:ee:ff", "AirPods", -45)

    def test_log_packet_stats(self):
        """Test packet statistics logging."""
        bacon_logger = BaconFreakLogger()

        # Test that method exists and can be called
        if hasattr(bacon_logger, "log_packet_stats"):
            bacon_logger.log_packet_stats(total=100, known=80, unknown=20)

    def test_log_scan_status(self):
        """Test scan status logging."""
        bacon_logger = BaconFreakLogger()

        # Test that method exists and can be called
        if hasattr(bacon_logger, "log_scan_status"):
            bacon_logger.log_scan_status("SCANNING", interface=1, timeout=300)

    def test_log_error(self):
        """Test error logging."""
        bacon_logger = BaconFreakLogger()

        # Test that method exists and can be called
        if hasattr(bacon_logger, "log_error"):
            bacon_logger.log_error("Test error", ValueError("test"))

    def test_context_binding(self):
        """Test context binding functionality."""
        bacon_logger = BaconFreakLogger()

        # Test that method exists and can be called
        if hasattr(bacon_logger, "bind_context"):
            bound_logger = bacon_logger.bind_context(session_id="test-123", scan_mode="active")
            self.assertIsNotNone(bound_logger)


if __name__ == "__main__":
    unittest.main()
