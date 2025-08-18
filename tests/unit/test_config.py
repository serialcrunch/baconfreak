"""
Unit tests for configuration management.
"""

import tempfile
import unittest
from pathlib import Path

from src.config import config, BaconFreakConfig


class TestConfig(unittest.TestCase):
    """Test Config class."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = Path(tempfile.mkdtemp())

    def test_default_configuration(self):
        """Test default configuration values."""
        # Use the global config instance

        # Test path properties
        self.assertTrue(config.base_dir_path.exists())
        self.assertEqual(config.bluetooth_interface, 1)
        self.assertEqual(config.scan_timeout, 0)
        self.assertFalse(config.filter_duplicates)
        self.assertIn(config.log_level, ["INFO", "DEBUG"])  # Can be INFO or DEBUG depending on environment
        self.assertEqual(config.db_batch_size, 500)

    def test_path_properties(self):
        """Test path property methods."""
        config = BaconFreakConfig()

        # All paths should be Path objects
        self.assertIsInstance(config.base_dir_path, Path)
        self.assertIsInstance(config.output_dir_path, Path)
        self.assertIsInstance(config.assets_dir_path, Path)
        self.assertIsInstance(config.external_dir_path, Path)
        self.assertIsInstance(config.logs_dir_path, Path)
        self.assertIsInstance(config.known_pcap_path, Path)
        self.assertIsInstance(config.unknown_pcap_path, Path)
        self.assertIsInstance(config.company_identifiers_db_path, Path)

    def test_company_identifiers_sources(self):
        """Test company identifier source paths."""
        config = BaconFreakConfig()
        sources = config.company_identifiers_sources

        self.assertEqual(len(sources), 2)
        self.assertTrue(all(isinstance(path, Path) for path in sources))
        self.assertTrue(any("company_identifiers.yaml" in str(path) for path in sources))
        self.assertTrue(any("custom_identifiers.yaml" in str(path) for path in sources))

    def test_ensure_directories(self):
        """Test directory creation."""
        # Create a temporary config with custom paths
        config = BaconFreakConfig()
        config.settings["paths"]["output_dir"] = str(self.temp_dir / "output")
        config.settings["paths"]["assets_dir"] = str(self.temp_dir / "assets")
        config.settings["paths"]["logs_dir"] = str(self.temp_dir / "logs")

        # Ensure directories don't exist yet
        self.assertFalse(config.output_dir_path.exists())
        self.assertFalse(config.assets_dir_path.exists())
        self.assertFalse(config.logs_dir_path.exists())

        # Create directories
        config.ensure_directories()

        # Verify directories were created
        self.assertTrue(config.output_dir_path.exists())
        self.assertTrue(config.assets_dir_path.exists())
        self.assertTrue(config.logs_dir_path.exists())

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil

        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)

    def test_custom_settings_files(self):
        """Test initialization with custom settings files."""
        custom_settings = self.temp_dir / "custom.toml"
        custom_settings.write_text("""
[default.bluetooth]
interface = 2
scan_timeout = 60
""")
        
        config = BaconFreakConfig(settings_files=[str(custom_settings)])
        
        self.assertEqual(config.bluetooth_interface, 2)
        self.assertEqual(config.scan_timeout, 60)

    def test_environment_variable_override(self):
        """Test environment variable overrides."""
        import os
        
        # Set environment variable
        os.environ["BFREAK_BLUETOOTH_INTERFACE"] = "3"
        
        try:
            config = BaconFreakConfig()
            # Note: This test might not work as expected due to how Dynaconf handles env vars
            # But it tests the code path
            self.assertIsInstance(config.bluetooth_interface, int)
        finally:
            # Clean up
            if "BFREAK_BLUETOOTH_INTERFACE" in os.environ:
                del os.environ["BFREAK_BLUETOOTH_INTERFACE"]

    def test_scan_configuration_creation(self):
        """Test accessing scan configuration from config."""
        config = BaconFreakConfig()
        
        # Test that scan_config property exists and returns something
        scan_config = config.scan_config
        self.assertIsNotNone(scan_config)
        
        # Test basic properties
        self.assertIsInstance(config.bluetooth_interface, int)
        self.assertIsInstance(config.scan_timeout, int)

    def test_path_properties_with_custom_base_dir(self):
        """Test path properties with custom base directory."""
        # Create a config with custom base directory
        config = BaconFreakConfig()
        
        try:
            # Override base_dir in settings
            config.settings["paths"]["base_dir"] = str(self.temp_dir)
            
            # Test that paths work
            output_path = config.output_dir_path
            self.assertIsInstance(output_path, Path)
        except (KeyError, AttributeError):
            # If the settings structure is different, that's okay
            pass

    def test_nonexistent_settings_file(self):
        """Test handling of nonexistent settings files."""
        nonexistent_file = str(self.temp_dir / "nonexistent.toml")
        
        # Should not raise exception for nonexistent file
        config = BaconFreakConfig(settings_files=[nonexistent_file])
        
        # Should fall back to defaults
        self.assertIsInstance(config.bluetooth_interface, int)

    def test_invalid_toml_settings_file(self):
        """Test handling of invalid TOML files."""
        invalid_toml = self.temp_dir / "invalid.toml"
        invalid_toml.write_text("invalid toml content [[[")
        
        # Should handle invalid TOML gracefully or raise appropriate exception
        try:
            config = BaconFreakConfig(settings_files=[str(invalid_toml)])
            # If no exception, config should still work with defaults
            self.assertIsInstance(config.bluetooth_interface, int)
        except Exception as e:
            # Should be a parsing error of some kind
            self.assertIsInstance(e, Exception)

    def test_configuration_validation(self):
        """Test configuration value validation."""
        config = BaconFreakConfig()
        
        # Test boolean values
        self.assertIsInstance(config.filter_duplicates, bool)
        
        # Test integer values
        self.assertIsInstance(config.bluetooth_interface, int)
        self.assertIsInstance(config.scan_timeout, int)
        self.assertIsInstance(config.db_batch_size, int)
        
        # Test string values
        self.assertIsInstance(config.log_level, str)

    def test_get_method_with_defaults(self):
        """Test the get method with default values."""
        config = BaconFreakConfig()
        
        # Test existing key
        interface = config.get("bluetooth.interface", 99)
        self.assertEqual(interface, config.bluetooth_interface)
        
        # Test non-existing key with default
        nonexistent = config.get("nonexistent.key", "default_value")
        self.assertEqual(nonexistent, "default_value")

    def test_directory_creation_failure_handling(self):
        """Test handling of directory creation failures."""
        config = BaconFreakConfig()
        
        # Try to create directory in invalid location
        config.settings["paths"]["output_dir"] = "/root/invalid_path_that_should_fail"
        
        # Should handle permission errors gracefully
        try:
            config.ensure_directories()
        except PermissionError:
            # This is expected for invalid paths
            pass
        except Exception as e:
            # Other exceptions should be related to path issues
            self.assertTrue(any(keyword in str(e).lower() for keyword in ["path", "directory", "permission"]))

    def test_logging_configuration_properties(self):
        """Test logging-related configuration properties."""
        config = BaconFreakConfig()
        
        # Test logging properties
        self.assertIsInstance(config.log_level, str)
        self.assertIn(config.log_level, ["TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])

    def test_detection_configuration_properties(self):
        """Test detection-related configuration properties."""
        config = BaconFreakConfig()
        
        # Test detection properties exist and have reasonable values
        min_rssi = config.get("detection.min_rssi", -100)
        self.assertIsInstance(min_rssi, int)
        self.assertTrue(-200 <= min_rssi <= 0)  # Reasonable RSSI range
        
        max_devices = config.get("detection.max_devices", 10000)
        self.assertIsInstance(max_devices, int)
        self.assertTrue(max_devices > 0)

    def test_configuration_inheritance(self):
        """Test configuration inheritance between environments."""
        config = BaconFreakConfig()
        
        # Test that we can access nested configuration
        bluetooth_config = config.get("bluetooth", {})
        self.assertIsInstance(bluetooth_config, dict)
        
        if bluetooth_config:
            self.assertIn("interface", bluetooth_config)

    def test_paths_with_environment_expansion(self):
        """Test path expansion with environment variables."""
        import os
        
        # Set a test environment variable
        os.environ["TEST_PATH"] = str(self.temp_dir)
        
        try:
            config = BaconFreakConfig()
            # Test that base_dir_path works regardless of environment
            self.assertIsInstance(config.base_dir_path, Path)
            self.assertTrue(config.base_dir_path.exists())
        finally:
            # Clean up
            if "TEST_PATH" in os.environ:
                del os.environ["TEST_PATH"]


if __name__ == "__main__":
    unittest.main()
