"""
Unit tests for WiFi OUI identifiers module.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import yaml
from peewee import SqliteDatabase
from pydantic import ValidationError

from src.plugins.wifi.oui_identifiers import (
    OUIDatabase,
    OUIIdentifier,
    OUIIdentifiers,
    OUIRecord,
    LastOUIUpdate,
)


class TestOUIRecord(unittest.TestCase):
    """Test OUIRecord Pydantic model."""

    def test_valid_oui_record(self):
        """Test valid OUI record creation."""
        record = OUIRecord(oui="00:11:22", vendor_name="Test Vendor")
        self.assertEqual(record.oui, "00:11:22")
        self.assertEqual(record.vendor_name, "Test Vendor")

    def test_oui_validation(self):
        """Test OUI format validation."""
        # Valid formats
        valid_ouis = ["00:11:22", "AA:BB:CC", "ff:ee:dd"]
        for oui in valid_ouis:
            record = OUIRecord(oui=oui, vendor_name="Test")
            self.assertEqual(record.oui, oui.upper())

        # Invalid formats
        invalid_ouis = ["001122", "00:11", "00:11:22:33", "GG:HH:II"]
        for oui in invalid_ouis:
            with self.assertRaises(ValidationError):
                OUIRecord(oui=oui, vendor_name="Test")

    def test_vendor_name_cleaning(self):
        """Test vendor name cleaning."""
        record = OUIRecord(oui="00:11:22", vendor_name="  Test Vendor  ")
        self.assertEqual(record.vendor_name, "Test Vendor")


class TestOUIDatabase(unittest.TestCase):
    """Test OUIDatabase validation."""

    def test_valid_oui_database(self):
        """Test valid OUI database creation."""
        data = {
            "oui_identifiers": [
                {"oui": "00:11:22", "vendor_name": "Vendor 1"},
                {"oui": "AA:BB:CC", "vendor_name": "Vendor 2"},
            ]
        }
        db = OUIDatabase(**data)
        self.assertEqual(len(db.oui_identifiers), 2)

    def test_duplicate_oui_validation(self):
        """Test duplicate OUI detection."""
        data = {
            "oui_identifiers": [
                {"oui": "00:11:22", "vendor_name": "Vendor 1"},
                {"oui": "00:11:22", "vendor_name": "Vendor 2"},  # Duplicate
            ]
        }
        with self.assertRaises(ValidationError):
            OUIDatabase(**data)


class TestOUIIdentifiers(unittest.TestCase):
    """Test OUIIdentifiers class."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.test_db_path = self.temp_dir / "test_oui.db"
        self.test_source_path = self.temp_dir / "test_oui.yaml"
        
        # Create test YAML source
        test_data = {
            "oui_identifiers": [
                {"oui": "00:05:02", "vendor_name": "Apple, Inc."},
                {"oui": "00:0C:29", "vendor_name": "VMware, Inc."},
                {"oui": "00:15:5D", "vendor_name": "Microsoft Corporation"},
            ]
        }
        with open(self.test_source_path, 'w') as f:
            yaml.dump(test_data, f)

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("src.plugins.wifi.oui_identifiers.config")
    def test_initialization(self, mock_config):
        """Test OUI identifiers initialization."""
        mock_config.oui_identifiers_db_path = self.test_db_path
        mock_config.oui_identifiers_sources = [self.test_source_path]
        
        oui_ids = OUIIdentifiers()
        self.assertIsNotNone(oui_ids)
        self.assertEqual(oui_ids.stats["lookups_performed"], 0)

    @patch("src.plugins.wifi.oui_identifiers.config")
    def test_mac_oui_extraction(self, mock_config):
        """Test OUI extraction from MAC addresses."""
        mock_config.oui_identifiers_db_path = self.test_db_path
        mock_config.oui_identifiers_sources = [self.test_source_path]
        
        oui_ids = OUIIdentifiers()
        
        # Test various MAC formats
        test_cases = [
            ("00:05:02:11:22:33", "00:05:02"),
            ("00-05-02-11-22-33", "00:05:02"),
            ("000502112233", "00:05:02"),
            ("00 05 02 11 22 33", "00:05:02"),
        ]
        
        for mac, expected_oui in test_cases:
            oui = oui_ids._extract_oui(mac)
            self.assertEqual(oui, expected_oui, f"Failed for MAC: {mac}")

    @patch("src.plugins.wifi.oui_identifiers.config")
    def test_invalid_mac_extraction(self, mock_config):
        """Test invalid MAC address handling."""
        mock_config.oui_identifiers_db_path = self.test_db_path
        mock_config.oui_identifiers_sources = [self.test_source_path]
        
        oui_ids = OUIIdentifiers()
        
        invalid_macs = [
            "00:05:02:11",  # Too short
            "00:05:02:11:22:33:44",  # Too long
            "XX:YY:ZZ:11:22:33",  # Invalid hex
            "",  # Empty
            "not-a-mac",  # Invalid format
        ]
        
        for mac in invalid_macs:
            oui = oui_ids._extract_oui(mac)
            self.assertIsNone(oui, f"Should be None for invalid MAC: {mac}")

    @patch("src.plugins.wifi.oui_identifiers.config")
    def test_vendor_lookup(self, mock_config):
        """Test vendor lookup functionality."""
        mock_config.oui_identifiers_db_path = self.test_db_path
        mock_config.oui_identifiers_sources = [self.test_source_path]
        
        oui_ids = OUIIdentifiers()
        
        # Test successful lookup
        vendor = oui_ids.lookup_vendor("00:05:02:11:22:33")
        self.assertEqual(vendor, "Apple, Inc.")
        
        # Test unknown OUI (global MAC)
        vendor = oui_ids.lookup_vendor("F0:DE:F1:11:22:33")
        self.assertIsNone(vendor)
        
        # Verify stats
        self.assertEqual(oui_ids.stats["lookups_performed"], 2)
        self.assertEqual(oui_ids.stats["successful_lookups"], 1)
        self.assertEqual(oui_ids.stats["failed_lookups"], 1)

    @patch("src.plugins.wifi.oui_identifiers.config")
    def test_caching(self, mock_config):
        """Test lookup caching."""
        mock_config.oui_identifiers_db_path = self.test_db_path
        mock_config.oui_identifiers_sources = [self.test_source_path]
        
        oui_ids = OUIIdentifiers()
        
        # First lookup (cache miss)
        vendor1 = oui_ids.lookup_vendor("00:05:02:11:22:33")
        self.assertEqual(vendor1, "Apple, Inc.")
        self.assertEqual(oui_ids.stats["cache_misses"], 1)
        self.assertEqual(oui_ids.stats["database_queries"], 1)
        
        # Second lookup (cache hit)
        vendor2 = oui_ids.lookup_vendor("00:05:02:44:55:66")
        self.assertEqual(vendor2, "Apple, Inc.")
        self.assertEqual(oui_ids.stats["cache_hits"], 1)
        self.assertEqual(oui_ids.stats["database_queries"], 1)  # Still 1

    @patch("src.plugins.wifi.oui_identifiers.config")
    def test_bulk_lookup(self, mock_config):
        """Test bulk lookup functionality."""
        mock_config.oui_identifiers_db_path = self.test_db_path
        mock_config.oui_identifiers_sources = [self.test_source_path]
        
        oui_ids = OUIIdentifiers()
        
        mac_addresses = [
            "00:05:02:11:22:33",  # Apple
            "00:0C:29:44:55:66",  # VMware
            "F0:DE:F1:77:88:99",  # Unknown (global MAC)
        ]
        
        results = oui_ids.bulk_lookup(mac_addresses)
        
        self.assertEqual(results["00:05:02:11:22:33"], "Apple, Inc.")
        self.assertEqual(results["00:0C:29:44:55:66"], "VMware, Inc.")
        self.assertIsNone(results["F0:DE:F1:77:88:99"])

    @patch("src.plugins.wifi.oui_identifiers.config")
    def test_statistics(self, mock_config):
        """Test statistics tracking."""
        mock_config.oui_identifiers_db_path = self.test_db_path
        mock_config.oui_identifiers_sources = [self.test_source_path]
        
        oui_ids = OUIIdentifiers()
        
        # Perform some lookups
        oui_ids.lookup_vendor("00:05:02:11:22:33")  # Success (Apple)
        oui_ids.lookup_vendor("F0:DE:F1:11:22:33")  # Failure (unknown global MAC)
        
        stats = oui_ids.get_statistics()
        
        # Check database stats
        self.assertIn("database", stats)
        self.assertGreater(stats["database"]["total_ouis"], 0)
        
        # Check performance stats
        self.assertIn("performance", stats)
        self.assertEqual(stats["performance"]["total_lookups"], 2)
        self.assertEqual(stats["performance"]["successful_lookups"], 1)
        self.assertEqual(stats["performance"]["failed_lookups"], 1)

    @patch("src.plugins.wifi.oui_identifiers.config")
    def test_cache_clear(self, mock_config):
        """Test cache clearing."""
        mock_config.oui_identifiers_db_path = self.test_db_path
        mock_config.oui_identifiers_sources = [self.test_source_path]
        
        oui_ids = OUIIdentifiers()
        
        # Populate cache
        oui_ids.lookup_vendor("00:05:02:11:22:33")
        self.assertGreater(len(oui_ids._cache), 0)
        
        # Clear cache
        oui_ids.clear_cache()
        self.assertEqual(len(oui_ids._cache), 0)

    @patch("src.plugins.wifi.oui_identifiers.config")
    def test_randomized_mac_detection(self, mock_config):
        """Test randomized MAC address detection."""
        mock_config.oui_identifiers_db_path = self.test_db_path
        mock_config.oui_identifiers_sources = [self.test_source_path]
        
        oui_ids = OUIIdentifiers()
        
        # Test globally administered MACs (LA bit = 0)
        global_macs = [
            "00:05:02:11:22:33",  # Apple
            "00:0C:29:44:55:66",  # VMware
            "F0:DE:F1:AB:CD:EF",  # Unknown global
        ]
        
        for mac in global_macs:
            self.assertFalse(oui_ids._is_randomized_mac(mac), 
                           f"Global MAC {mac} incorrectly detected as randomized")
        
        # Test locally administered/randomized MACs (LA bit = 1)
        randomized_macs = [
            "02:00:00:00:00:00",  # iOS random
            "06:12:34:56:78:90",  # Android random
            "0A:BB:CC:DD:EE:FF",  # Windows random
            "12:34:56:78:90:AB",  # Generic random
            "FF:FF:FF:FF:FF:FF",  # Broadcast (LA bit set)
        ]
        
        for mac in randomized_macs:
            self.assertTrue(oui_ids._is_randomized_mac(mac), 
                          f"Randomized MAC {mac} not detected as randomized")

    @patch("src.plugins.wifi.oui_identifiers.config")
    def test_randomized_mac_vendor_lookup(self, mock_config):
        """Test vendor lookup returns 'Randomized' for randomized MACs."""
        mock_config.oui_identifiers_db_path = self.test_db_path
        mock_config.oui_identifiers_sources = [self.test_source_path]
        
        oui_ids = OUIIdentifiers()
        
        # Test that randomized MACs return "Randomized"
        randomized_macs = [
            "02:05:02:11:22:33",  # Would be Apple if global
            "06:0C:29:44:55:66",  # Would be VMware if global  
            "0A:12:34:56:78:90",  # Random
        ]
        
        for mac in randomized_macs:
            vendor = oui_ids.lookup_vendor(mac)
            self.assertEqual(vendor, "Randomized", 
                           f"Randomized MAC {mac} should return 'Randomized', got {vendor}")
        
        # Test that global MACs still work normally
        vendor = oui_ids.lookup_vendor("00:05:02:11:22:33")
        self.assertEqual(vendor, "Apple, Inc.")
        
        # Test statistics
        self.assertGreater(oui_ids.stats["successful_lookups"], 0)
        self.assertEqual(oui_ids.stats["failed_lookups"], 0)


class TestDatabaseModels(unittest.TestCase):
    """Test database models."""

    def setUp(self):
        """Set up test database."""
        self.test_db = SqliteDatabase(':memory:')
        self.test_db.bind([OUIIdentifier, LastOUIUpdate])
        self.test_db.create_tables([OUIIdentifier, LastOUIUpdate])

    def tearDown(self):
        """Clean up test database."""
        self.test_db.drop_tables([OUIIdentifier, LastOUIUpdate])
        self.test_db.close()

    def test_oui_identifier_model(self):
        """Test OUIIdentifier model."""
        # Create OUI identifier
        oui_id = OUIIdentifier.create(oui="00:11:22", vendor_name="Test Vendor")
        self.assertEqual(oui_id.oui, "00:11:22")
        self.assertEqual(oui_id.vendor_name, "Test Vendor")
        
        # Retrieve from database
        retrieved = OUIIdentifier.get(OUIIdentifier.oui == "00:11:22")
        self.assertEqual(retrieved.vendor_name, "Test Vendor")

    def test_last_update_model(self):
        """Test LastOUIUpdate model."""
        # Create update record
        update = LastOUIUpdate.create(timestamp="2024-01-01T00:00:00", record_count=100)
        self.assertEqual(update.record_count, 100)
        
        # Retrieve from database
        retrieved = LastOUIUpdate.get(LastOUIUpdate.id == 1)
        self.assertEqual(retrieved.record_count, 100)


if __name__ == "__main__":
    unittest.main()