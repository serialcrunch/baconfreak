"""
Unit tests for modern Pydantic models.
"""

from datetime import datetime, timedelta

import pytest
from pydantic import ValidationError

from src.models import (
    BluetoothDevice,
    DeviceConstants,
    DeviceStats,
    DeviceType,
    PacketInfo,
    ScanConfiguration,
)


class TestBluetoothDevice:
    """Test BluetoothDevice Pydantic model."""

    def test_valid_device_creation(self):
        """Test creating a valid Bluetooth device."""
        device = BluetoothDevice(
            addr="aa:bb:cc:dd:ee:ff",
            device_type=DeviceType.AIRPODS,
            rssi=-45,
            data="121918abcdef",
            company_id=76,
            company_name="Apple, Inc.",
        )

        assert device.addr == "aa:bb:cc:dd:ee:ff"
        assert device.device_type == DeviceType.AIRPODS
        assert device.rssi == -45
        assert device.company_id == 76
        assert device.packet_count == 1
        assert isinstance(device.first_seen, datetime)
        assert isinstance(device.id, str)

    def test_mac_address_normalization(self):
        """Test MAC address normalization to lowercase."""
        device = BluetoothDevice(addr="AA:BB:CC:DD:EE:FF", device_type=DeviceType.UNKNOWN, rssi=-50)

        assert device.addr == "aa:bb:cc:dd:ee:ff"

    def test_invalid_mac_address(self):
        """Test validation of invalid MAC addresses."""
        with pytest.raises(ValidationError):
            BluetoothDevice(addr="invalid-mac", device_type=DeviceType.UNKNOWN, rssi=-50)

    def test_rssi_validation(self):
        """Test RSSI value validation."""
        # Valid RSSI
        device = BluetoothDevice(addr="aa:bb:cc:dd:ee:ff", device_type=DeviceType.UNKNOWN, rssi=-50)
        assert device.rssi == -50

        # Invalid RSSI (too low)
        with pytest.raises(ValidationError):
            BluetoothDevice(addr="aa:bb:cc:dd:ee:ff", device_type=DeviceType.UNKNOWN, rssi=-200)

        # Invalid RSSI (too high)
        with pytest.raises(ValidationError):
            BluetoothDevice(addr="aa:bb:cc:dd:ee:ff", device_type=DeviceType.UNKNOWN, rssi=50)

    def test_hex_data_validation(self):
        """Test hexadecimal data validation."""
        # Valid hex data
        device = BluetoothDevice(
            addr="aa:bb:cc:dd:ee:ff", device_type=DeviceType.UNKNOWN, rssi=-50, data="deadbeef123"
        )
        assert device.data == "deadbeef123"

        # Invalid hex data
        with pytest.raises(ValidationError):
            BluetoothDevice(
                addr="aa:bb:cc:dd:ee:ff",
                device_type=DeviceType.UNKNOWN,
                rssi=-50,
                data="invalid_hex_xyz",
            )

    def test_update_seen(self):
        """Test updating device observation."""
        device = BluetoothDevice(addr="aa:bb:cc:dd:ee:ff", device_type=DeviceType.UNKNOWN, rssi=-50)

        original_first_seen = device.first_seen
        original_packet_count = device.packet_count

        # Wait a small amount to ensure time difference
        import time

        time.sleep(0.01)

        device.update_seen(rssi=-40, data="deadbeef", device_name="Test Device")

        assert device.rssi == -40
        assert device.data == "deadbeef"
        assert device.device_name == "Test Device"
        assert device.packet_count == original_packet_count + 1
        assert device.first_seen == original_first_seen  # Should not change
        assert device.last_seen > original_first_seen

    def test_tags_management(self):
        """Test tag addition and removal."""
        device = BluetoothDevice(addr="aa:bb:cc:dd:ee:ff", device_type=DeviceType.UNKNOWN, rssi=-50)

        # Add tags
        device.add_tag("test_tag")
        device.add_tag("another_tag")

        assert "test_tag" in device.tags
        assert "another_tag" in device.tags
        assert len(device.tags) == 2

        # Try to add duplicate
        device.add_tag("test_tag")
        assert len(device.tags) == 2  # Should not add duplicate

        # Remove tag
        device.remove_tag("test_tag")
        assert "test_tag" not in device.tags
        assert len(device.tags) == 1

    def test_age_properties(self):
        """Test age calculation properties."""
        device = BluetoothDevice(addr="aa:bb:cc:dd:ee:ff", device_type=DeviceType.UNKNOWN, rssi=-50)

        # Test age_seconds
        age = device.age_seconds
        assert age >= 0
        assert age < 1  # Should be very recent

        # Test last_seen_seconds_ago
        last_seen_age = device.last_seen_seconds_ago
        assert last_seen_age >= 0
        assert last_seen_age < 1

        # Test is_stale
        assert not device.is_stale(threshold_seconds=300)  # 5 minutes
        assert device.is_stale(threshold_seconds=0)  # 0 seconds


class TestPacketInfo:
    """Test PacketInfo Pydantic model."""

    def test_valid_packet_info(self):
        """Test creating valid packet info."""
        packet_info = PacketInfo(
            addr="aa:bb:cc:dd:ee:ff", rssi=-45, data="deadbeef", company_id=76, service_uuid=65261
        )

        assert packet_info.addr == "aa:bb:cc:dd:ee:ff"
        assert packet_info.rssi == -45
        assert packet_info.company_id == 76
        assert packet_info.service_uuid == 65261
        assert isinstance(packet_info.timestamp, datetime)

    def test_mac_address_normalization(self):
        """Test MAC address normalization in PacketInfo."""
        packet_info = PacketInfo(addr="AA:BB:CC:DD:EE:FF", rssi=-45)

        assert packet_info.addr == "aa:bb:cc:dd:ee:ff"


class TestDeviceStats:
    """Test DeviceStats Pydantic model."""

    def test_valid_device_stats(self):
        """Test creating valid device statistics."""
        stats = DeviceStats()

        assert stats.total_packets == 0
        assert stats.unique_devices == 0
        assert isinstance(stats.session_id, str)
        assert isinstance(stats.start_time, datetime)
        assert stats.end_time is None

    def test_session_duration(self):
        """Test session duration calculation."""
        stats = DeviceStats()

        # Test with no end time (ongoing session)
        duration = stats.session_duration_seconds
        assert duration >= 0
        assert duration < 1  # Should be very recent

        # Test with end time
        stats.end_time = stats.start_time + timedelta(seconds=60)
        assert stats.session_duration_seconds == 60.0

    def test_error_rate_calculation(self):
        """Test error rate calculation."""
        stats = DeviceStats()

        # No packets processed
        assert stats.error_rate == 0.0

        # Some packets processed
        stats.total_packets = 100
        stats.valid_packets = 95
        assert stats.error_rate == 0.05  # 5% error rate

    def test_add_device(self):
        """Test adding device to statistics."""
        stats = DeviceStats()

        device = BluetoothDevice(
            addr="aa:bb:cc:dd:ee:ff",
            device_type=DeviceType.AIRPODS,
            rssi=-50,
            company_name="Apple, Inc.",
        )

        stats.add_device(device)

        assert stats.unique_devices == 1
        assert stats.devices_by_type[DeviceType.AIRPODS] == 1
        assert "Apple, Inc." in stats.known_companies


class TestScanConfiguration:
    """Test ScanConfiguration Pydantic model."""

    def test_valid_scan_config(self):
        """Test creating valid scan configuration."""
        config = ScanConfiguration(interface="hci1", scan_timeout=300, min_rssi=-80, log_level="DEBUG")

        assert config.interface == "hci1"
        assert config.scan_timeout == 300
        assert config.min_rssi == -80
        assert config.log_level == "DEBUG"

    def test_log_level_validation(self):
        """Test log level validation."""
        # Valid log levels
        for level in ["TRACE", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            config = ScanConfiguration(log_level=level)
            assert config.log_level == level

        # Invalid log level
        with pytest.raises(ValidationError):
            ScanConfiguration(log_level="INVALID")

    def test_rssi_bounds(self):
        """Test RSSI bounds validation."""
        # Valid RSSI
        config = ScanConfiguration(min_rssi=-100)
        assert config.min_rssi == -100

        # Invalid RSSI (too low)
        with pytest.raises(ValidationError):
            ScanConfiguration(min_rssi=-200)

        # Invalid RSSI (too high)
        with pytest.raises(ValidationError):
            ScanConfiguration(min_rssi=50)


class TestDeviceConstants:
    """Test DeviceConstants values."""

    def test_constants_values(self):
        """Test that constants have expected values."""
        assert DeviceConstants.TILE_SERVICE_UUID == 65261
        assert DeviceConstants.APPLE_COMPANY_ID == 76
        assert DeviceConstants.MICROSOFT_COMPANY_ID == 6

        # Test Apple signatures
        assert "0719" in DeviceConstants.APPLE_SIGNATURES
        assert DeviceConstants.APPLE_SIGNATURES["0719"] == DeviceType.AIRTAG_UNREGISTERED
        assert DeviceConstants.APPLE_SIGNATURES["121918"] == DeviceType.AIRPODS

        # Test RSSI thresholds
        assert DeviceConstants.RSSI_EXCELLENT > DeviceConstants.RSSI_GOOD
        assert DeviceConstants.RSSI_GOOD > DeviceConstants.RSSI_FAIR
        assert DeviceConstants.RSSI_FAIR > DeviceConstants.RSSI_POOR
