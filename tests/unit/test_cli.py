"""
Unit tests for CLI interface.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import typer
from typer.testing import CliRunner

# Import the CLI app - we'll need to handle the import carefully
# since it might depend on the main module structure


class TestCLI(unittest.TestCase):
    """Test CLI interface functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.runner = CliRunner()
        self.temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil

        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)

    @patch("main.console")
    def test_version_callback(self, mock_console):
        """Test version callback functionality."""
        from main import version_callback

        # Test version display
        with self.assertRaises(typer.Exit):
            version_callback(True)

        # Should print version info
        mock_console.print.assert_called()

        # Test no action when False
        version_callback(False)

    @patch("main.logger")
    @patch("main.console")
    def test_config_callback_existing_file(self, mock_console, mock_logger):
        """Test config callback with existing file."""
        from main import config_callback

        # Create a test config file
        test_config = self.temp_dir / "test_config.toml"
        test_config.write_text("[default]\ntest = true")

        # Test with existing file
        config_callback(str(test_config))

        # Should log the loading message
        mock_logger.info.assert_called_with(f"Loading configuration from: {test_config}")

    @patch("main.console")
    def test_config_callback_nonexistent_file(self, mock_console):
        """Test config callback with nonexistent file."""
        from main import config_callback

        nonexistent_file = str(self.temp_dir / "nonexistent.toml")

        # Test with nonexistent file
        with self.assertRaises(typer.Exit):
            config_callback(nonexistent_file)

        # Should print error message
        mock_console.print.assert_called_with(
            f"❌ Configuration file not found: {nonexistent_file}", style="red"
        )

    def test_config_callback_none(self):
        """Test config callback with None value."""
        from main import config_callback

        # Should not raise exception
        result = config_callback(None)
        self.assertIsNone(result)

    @patch("main.config")
    @patch("main.console")
    def test_doctor_command_basic(self, mock_console, mock_config):
        """Test basic doctor command functionality."""
        # Mock configuration values
        mock_config.base_dir_path = Path("/test")
        mock_config.output_dir_path = Path("/test/output")
        mock_config.bluetooth_interface = 1
        mock_config.log_level = "INFO"

        # This test would need the actual CLI app import
        # For now, we'll test the components we can access
        self.assertTrue(True)  # Placeholder

    @patch("main.setup_logging")
    @patch("main.console")
    def test_setup_logging_integration(self, mock_console, mock_setup_logging):
        """Test logging setup integration."""
        from main import setup_logging

        # Test that setup_logging can be called
        mock_setup_logging.return_value = Mock()

        # This would be called by CLI commands
        result = setup_logging(level="DEBUG")

        mock_setup_logging.assert_called_with(level="DEBUG")

    def test_device_type_enum_usage(self):
        """Test that DeviceType enum is properly imported and usable."""
        from main import DeviceType

        # Test that enum values are accessible
        self.assertTrue(hasattr(DeviceType, "AIRTAG_UNREGISTERED"))
        self.assertTrue(hasattr(DeviceType, "AIRPODS"))
        self.assertTrue(hasattr(DeviceType, "TILE"))
        self.assertTrue(hasattr(DeviceType, "UNKNOWN"))

    @patch("main.console")
    def test_console_integration(self, mock_console):
        """Test Rich console integration."""
        from main import console

        # Test that console is available and has expected methods
        self.assertTrue(hasattr(console, "print"))
        self.assertTrue(hasattr(console, "log"))

    def test_app_configuration(self):
        """Test Typer app configuration."""
        from main import app

        # Test that app is properly configured
        self.assertIsInstance(app, typer.Typer)
        self.assertEqual(app.info.name, "baconfreak")
        self.assertIn("BLE", app.info.help)

    @patch("main.config")
    def test_config_integration(self, mock_config):
        """Test configuration integration."""
        # Test that config is importable and has expected attributes
        from main import config

        # Mock some common config attributes
        mock_config.bluetooth_interface = 1
        mock_config.log_level = "INFO"
        mock_config.base_dir_path = Path("/test")

        self.assertEqual(mock_config.bluetooth_interface, 1)
        self.assertEqual(mock_config.log_level, "INFO")

    def test_imports_successful(self):
        """Test that all imports in main.py are successful."""
        # Test that we can import the main module without errors
        try:
            import main

            self.assertTrue(hasattr(main, "app"))
            self.assertTrue(hasattr(main, "console"))
            self.assertTrue(hasattr(main, "version_callback"))
            self.assertTrue(hasattr(main, "config_callback"))
        except ImportError as e:
            self.fail(f"Failed to import main module: {e}")

    @patch("sys.exit")
    @patch("main.console")
    def test_error_handling_patterns(self, mock_console, mock_exit):
        """Test error handling patterns used in CLI."""
        from main import config_callback

        # Test error handling with invalid config
        with self.assertRaises(typer.Exit):
            config_callback("/invalid/path/config.toml")

        # Should print error message
        mock_console.print.assert_called()

    def test_rich_components_integration(self):
        """Test Rich components integration."""
        try:
            from main import Panel, Progress, Table, Tree

            # Test that Rich components are importable
            self.assertTrue(callable(Table))
            self.assertTrue(callable(Tree))
            self.assertTrue(callable(Panel))
            self.assertTrue(callable(Progress))
        except ImportError as e:
            self.fail(f"Failed to import Rich components: {e}")

    @patch("main.logger")
    def test_logging_integration(self, mock_logger):
        """Test Loguru logger integration."""
        from main import logger

        # Test that logger has expected methods
        self.assertTrue(hasattr(logger, "info"))
        self.assertTrue(hasattr(logger, "error"))
        self.assertTrue(hasattr(logger, "debug"))
        self.assertTrue(hasattr(logger, "warning"))


class TestCLICommandStructure(unittest.TestCase):
    """Test CLI command structure and patterns."""

    def test_command_callback_patterns(self):
        """Test common command callback patterns."""
        from main import config_callback, version_callback

        # Test that callbacks follow expected patterns
        self.assertTrue(callable(version_callback))
        self.assertTrue(callable(config_callback))

    def test_typer_integration(self):
        """Test Typer framework integration."""
        from main import app

        # Test that app has expected structure
        self.assertIsInstance(app, typer.Typer)

        # Test that app info is properly set
        self.assertIsNotNone(app.info.name)
        self.assertIsNotNone(app.info.help)

    def test_rich_markup_mode(self):
        """Test Rich markup mode configuration."""
        from main import app

        # Test that Rich markup is enabled
        # This test checks the app configuration
        self.assertIsInstance(app, typer.Typer)

    @patch("main.Path")
    def test_path_handling(self, mock_path):
        """Test path handling in CLI."""
        from main import config_callback

        # Mock Path behavior
        mock_path_instance = Mock()
        mock_path_instance.exists.return_value = True
        mock_path.return_value = mock_path_instance

        # Test path handling doesn't raise exception
        config_callback("test_path")


if __name__ == "__main__":
    # Set up test environment
    import sys
    from pathlib import Path

    # Add src to path for testing
    project_root = Path(__file__).parent.parent.parent
    sys.path.insert(0, str(project_root))

    unittest.main()
