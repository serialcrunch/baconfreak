"""Tests for utility functions."""

import unittest
from datetime import timedelta

from src.utils import (
    format_rssi_with_quality,
    format_time_delta,
    normalize_mac_address,
    truncate_string,
)


class TestUtils(unittest.TestCase):
    """Test utility functions."""

    def test_format_time_delta_with_timedelta(self):
        """Test formatting timedelta objects."""
        self.assertEqual(format_time_delta(timedelta(seconds=30)), "30s")
        self.assertEqual(format_time_delta(timedelta(minutes=5)), "5m")
        self.assertEqual(format_time_delta(timedelta(hours=2, minutes=30)), "2h30m")
        self.assertEqual(format_time_delta(timedelta(days=1, hours=3)), "1d3h")

    def test_format_time_delta_with_float(self):
        """Test formatting float seconds."""
        self.assertEqual(format_time_delta(30.0), "30s")
        self.assertEqual(format_time_delta(300.0), "5m")
        self.assertEqual(format_time_delta(9000.0), "2h30m")

    def test_normalize_mac_address(self):
        """Test MAC address normalization."""
        # Test various formats
        self.assertEqual(normalize_mac_address("AA:BB:CC:DD:EE:FF"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(normalize_mac_address("aa-bb-cc-dd-ee-ff"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(normalize_mac_address("aabbccddeeff"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(normalize_mac_address("aa.bb.cc.dd.ee.ff"), "aa:bb:cc:dd:ee:ff")

    def test_normalize_mac_address_invalid(self):
        """Test invalid MAC addresses."""
        with self.assertRaises(ValueError):
            normalize_mac_address("invalid")
        with self.assertRaises(ValueError):
            normalize_mac_address("aa:bb:cc:dd:ee")  # Too short
        with self.assertRaises(ValueError):
            normalize_mac_address("xx:yy:zz:dd:ee:ff")  # Invalid hex

    def test_format_rssi_with_quality(self):
        """Test RSSI formatting with quality indicators."""
        value, style = format_rssi_with_quality(-40)
        self.assertEqual(value, "-40")
        self.assertEqual(style, "green")

        value, style = format_rssi_with_quality(-60)
        self.assertEqual(value, "-60")
        self.assertEqual(style, "yellow")

        value, style = format_rssi_with_quality(-80)
        self.assertEqual(value, "-80")
        self.assertEqual(style, "red")

    def test_truncate_string(self):
        """Test string truncation."""
        self.assertEqual(truncate_string("hello", 10), "hello")
        self.assertEqual(truncate_string("hello world", 8), "hello...")
        self.assertEqual(truncate_string("test", 8, "!!"), "test")
        self.assertEqual(truncate_string("hello world", 8, "!!"), "hello !!")


if __name__ == "__main__":
    unittest.main()
