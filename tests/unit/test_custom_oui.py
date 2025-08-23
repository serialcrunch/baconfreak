"""
Unit tests for custom OUI identifiers functionality.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from src.plugins.wifi.oui_identifiers import OUIIdentifiers


class TestCustomOUIIdentifiers(unittest.TestCase):
    """Test custom OUI identifiers functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.test_db_path = self.temp_dir / "test_oui.db"
        self.main_source_path = self.temp_dir / "main_oui.yaml"
        self.custom_source_path = self.temp_dir / "custom_oui.yaml"
        
        # Create main OUI source
        main_data = {
            "oui_identifiers": [
                {"oui": "00:05:02", "vendor_name": "Apple, Inc."},
                {"oui": "00:0C:29", "vendor_name": "VMware, Inc."},
            ]
        }
        with open(self.main_source_path, 'w') as f:
            yaml.dump(main_data, f)
            
        # Create custom OUI source
        custom_data = {
            "oui_identifiers": [
                {"oui": "02:42:00", "vendor_name": "Docker Container"},
                {"oui": "52:54:00", "vendor_name": "QEMU/KVM Virtual NIC"},
                {"oui": "00:05:02", "vendor_name": "Apple MacBook Pro"},  # Override
            ]
        }
        with open(self.custom_source_path, 'w') as f:
            yaml.dump(custom_data, f)

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("src.plugins.wifi.oui_identifiers.config")
    def test_custom_oui_loading(self, mock_config):
        """Test that custom OUIs are loaded alongside main OUIs."""
        mock_config.oui_identifiers_db_path = self.test_db_path
        mock_config.oui_identifiers_sources = [self.main_source_path, self.custom_source_path]
        
        oui_ids = OUIIdentifiers()
        
        # Test main OUI
        vendor = oui_ids.lookup_vendor("00:0C:29:11:22:33")
        self.assertEqual(vendor, "VMware, Inc.")
        
        # Test custom OUI
        vendor = oui_ids.lookup_vendor("02:42:00:11:22:33")
        self.assertEqual(vendor, "Docker Container")
        
        # Test another custom OUI
        vendor = oui_ids.lookup_vendor("52:54:00:11:22:33")
        self.assertEqual(vendor, "QEMU/KVM Virtual NIC")

    @patch("src.plugins.wifi.oui_identifiers.config")
    def test_custom_oui_override(self, mock_config):
        """Test that custom OUIs can override main OUIs."""
        mock_config.oui_identifiers_db_path = self.test_db_path
        mock_config.oui_identifiers_sources = [self.main_source_path, self.custom_source_path]
        
        oui_ids = OUIIdentifiers()
        
        # This OUI appears in both files, custom should override
        vendor = oui_ids.lookup_vendor("00:05:02:11:22:33")
        self.assertEqual(vendor, "Apple MacBook Pro")  # Custom override, not "Apple, Inc."

    @patch("src.plugins.wifi.oui_identifiers.config")
    def test_missing_custom_file_graceful(self, mock_config):
        """Test that missing custom file is handled gracefully."""
        missing_custom_path = self.temp_dir / "missing_custom.yaml"
        
        mock_config.oui_identifiers_db_path = self.test_db_path
        mock_config.oui_identifiers_sources = [self.main_source_path, missing_custom_path]
        
        # Should not raise exception
        oui_ids = OUIIdentifiers()
        
        # Main OUIs should still work
        vendor = oui_ids.lookup_vendor("00:05:02:11:22:33")
        self.assertEqual(vendor, "Apple, Inc.")  # Original, no override

    @patch("src.plugins.wifi.oui_identifiers.config")
    def test_private_oui_recognition(self, mock_config):
        """Test recognition of private/locally administered OUIs."""
        mock_config.oui_identifiers_db_path = self.test_db_path
        mock_config.oui_identifiers_sources = [self.custom_source_path]
        
        oui_ids = OUIIdentifiers()
        
        # Test locally administered OUI (bit 1 of first octet is set)
        vendor = oui_ids.lookup_vendor("02:42:00:11:22:33")  # 02 = 00000010 (bit 1 set)
        self.assertEqual(vendor, "Docker Container")
        
        # Test QEMU/KVM virtual NIC
        vendor = oui_ids.lookup_vendor("52:54:00:11:22:33")  # 52 = 01010010 (bit 1 set)
        self.assertEqual(vendor, "QEMU/KVM Virtual NIC")

    @patch("src.plugins.wifi.oui_identifiers.config")
    def test_custom_oui_statistics(self, mock_config):
        """Test that statistics include custom OUIs."""
        mock_config.oui_identifiers_db_path = self.test_db_path
        mock_config.oui_identifiers_sources = [self.main_source_path, self.custom_source_path]
        
        oui_ids = OUIIdentifiers()
        
        # Perform some lookups
        oui_ids.lookup_vendor("00:05:02:11:22:33")  # Custom override
        oui_ids.lookup_vendor("02:42:00:11:22:33")  # Custom only
        oui_ids.lookup_vendor("00:0C:29:11:22:33")  # Main only
        
        stats = oui_ids.get_statistics()
        
        # Should have records from both files (with override considered)
        # Main: 2 records, Custom: 3 records, but 1 override = 4 unique OUIs
        self.assertGreaterEqual(stats["database"]["total_ouis"], 4)
        self.assertEqual(stats["performance"]["total_lookups"], 3)
        self.assertEqual(stats["performance"]["successful_lookups"], 3)


if __name__ == "__main__":
    unittest.main()