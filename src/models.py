"""
Modern data models using Pydantic for Bluetooth device tracking.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic.dataclasses import dataclass as pydantic_dataclass


class DeviceType(str, Enum):
    """Enumeration of supported device types."""

    TILE = "tile"
    AIRTAG_UNREGISTERED = "airtag_unregistered"
    AIRTAG_REGISTERED = "airtag_registered"
    AIRPODS = "airpods"
    APPLE_UNKNOWN = "apple_unknown"
    UNKNOWN = "unknown"


class BluetoothDevice(BaseModel):
    """Pydantic model for Bluetooth device tracking."""

    model_config = ConfigDict(validate_assignment=True, str_strip_whitespace=True, frozen=False)

    # Core device information
    addr: str = Field(
        ..., description="Bluetooth MAC address", pattern=r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$"
    )
    device_type: DeviceType = Field(..., description="Type of device detected")
    rssi: int = Field(..., description="Signal strength in dBm", ge=-127, le=20)

    # Optional fields
    data: Optional[str] = Field(None, description="Hex string of advertisement data")
    company_id: Optional[int] = Field(
        None, description="Bluetooth SIG company identifier", ge=0, le=65535
    )
    company_name: Optional[str] = Field(None, description="Company name from BT SIG registry")
    device_name: Optional[str] = Field(None, description="Device name if available")

    # Tracking information
    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique device session ID")
    first_seen: datetime = Field(
        default_factory=datetime.now, description="First detection timestamp"
    )
    last_seen: datetime = Field(
        default_factory=datetime.now, description="Last detection timestamp"
    )
    packet_count: int = Field(default=1, description="Number of packets received", ge=1)

    # Metadata
    tags: List[str] = Field(default_factory=list, description="Custom tags for categorization")
    confidence: float = Field(default=1.0, description="Detection confidence score", ge=0.0, le=1.0)

    @field_validator("data")
    @classmethod
    def validate_hex_data(cls, v):
        """Validate that data is a valid hex string."""
        if v is not None and v:
            try:
                int(v, 16)
            except ValueError:
                raise ValueError("Data must be a valid hexadecimal string")
        return v

    @field_validator("addr")
    @classmethod
    def normalize_mac_address(cls, v):
        """Normalize MAC address to lowercase with colons."""
        return v.lower()

    def update_seen(
        self, rssi: int, data: Optional[str] = None, device_name: Optional[str] = None
    ) -> None:
        """Update device with new observation."""
        self.last_seen = datetime.now()
        self.rssi = rssi
        if data:
            self.data = data
        if device_name:
            self.device_name = device_name
        self.packet_count += 1

    def add_tag(self, tag: str) -> None:
        """Add a tag to the device."""
        if tag not in self.tags:
            self.tags.append(tag)

    def remove_tag(self, tag: str) -> None:
        """Remove a tag from the device."""
        if tag in self.tags:
            self.tags.remove(tag)

    @property
    def age_seconds(self) -> float:
        """Get the age of the device in seconds since first seen."""
        return (datetime.now() - self.first_seen).total_seconds()

    @property
    def last_seen_seconds_ago(self) -> float:
        """Get seconds since last seen."""
        return (datetime.now() - self.last_seen).total_seconds()

    def is_stale(self, threshold_seconds: int = 300) -> bool:
        """Check if device hasn't been seen recently (default 5 minutes)."""
        return self.last_seen_seconds_ago > threshold_seconds


class PacketInfo(BaseModel):
    """Pydantic model for packet information extracted from Bluetooth packets."""

    model_config = ConfigDict(validate_assignment=True, str_strip_whitespace=True)

    addr: str = Field(..., description="Bluetooth MAC address")
    rssi: int = Field(..., description="Signal strength in dBm", ge=-127, le=20)
    timestamp: datetime = Field(
        default_factory=datetime.now, description="Packet capture timestamp"
    )

    # Optional packet data
    data: Optional[str] = Field(None, description="Raw advertisement data as hex string")
    company_id: Optional[int] = Field(None, description="Company identifier", ge=0, le=65535)
    service_uuid: Optional[int] = Field(None, description="Service UUID", ge=0)
    device_name: Optional[str] = Field(None, description="Device name from advertisement")
    tx_power: Optional[int] = Field(None, description="Transmission power level")

    # Metadata
    interface: Optional[str] = Field(None, description="Bluetooth interface used")
    raw_packet: Optional[Any] = Field(None, description="Raw scapy packet object", exclude=True)

    @field_validator("addr")
    @classmethod
    def normalize_mac_address(cls, v):
        """Normalize MAC address to lowercase."""
        return v.lower()


class DeviceStats(BaseModel):
    """Statistics for device detection session."""

    model_config = ConfigDict(validate_assignment=True)

    session_id: str = Field(default_factory=lambda: str(uuid4()), description="Session identifier")
    start_time: datetime = Field(default_factory=datetime.now, description="Session start time")
    end_time: Optional[datetime] = Field(None, description="Session end time")

    # Packet statistics
    total_packets: int = Field(default=0, description="Total packets processed", ge=0)
    valid_packets: int = Field(default=0, description="Valid BLE advertisement packets", ge=0)

    # Device statistics
    unique_devices: int = Field(default=0, description="Number of unique devices detected", ge=0)
    devices_by_type: Dict[DeviceType, int] = Field(
        default_factory=dict, description="Device count by type"
    )

    # Company statistics
    known_companies: set[str] = Field(
        default_factory=set, description="Known company names encountered"
    )
    unknown_company_ids: set[int] = Field(
        default_factory=set, description="Unknown company IDs encountered"
    )

    # Performance metrics
    packets_per_second: float = Field(default=0.0, description="Average packets per second", ge=0.0)

    @property
    def session_duration_seconds(self) -> float:
        """Get session duration in seconds."""
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()

    @property
    def error_rate(self) -> float:
        """Calculate packet error rate."""
        if self.total_packets == 0:
            return 0.0
        return (self.total_packets - self.valid_packets) / self.total_packets

    def update_packets_per_second(self) -> None:
        """Update packets per second calculation."""
        duration = self.session_duration_seconds
        if duration > 0:
            self.packets_per_second = self.total_packets / duration

    def add_device(self, device: BluetoothDevice) -> None:
        """Add a device to statistics."""
        self.unique_devices += 1
        device_type = device.device_type
        self.devices_by_type[device_type] = self.devices_by_type.get(device_type, 0) + 1

        if device.company_name:
            self.known_companies.add(device.company_name)
        elif device.company_id is not None:
            self.unknown_company_ids.add(device.company_id)


class ScanConfiguration(BaseModel):
    """Configuration for Bluetooth scanning."""

    model_config = ConfigDict(validate_assignment=True, str_strip_whitespace=True)

    # Interface settings
    interface: int = Field(default=1, description="Bluetooth HCI interface number", ge=0)
    scan_timeout: int = Field(default=0, description="Scan timeout in seconds (0 = infinite)", ge=0)
    filter_duplicates: bool = Field(default=False, description="Filter duplicate advertisements")

    # Output settings
    output_dir: str = Field(default="output", description="Output directory for files")
    known_pcap_filename: str = Field(
        default="bt-known.pcap", description="PCAP file for known devices"
    )
    unknown_pcap_filename: str = Field(
        default="bt-unknown.pcap", description="PCAP file for unknown devices"
    )

    # Detection settings
    device_timeout: int = Field(
        default=300, description="Device staleness timeout in seconds", gt=0
    )
    min_rssi: int = Field(default=-100, description="Minimum RSSI to consider", ge=-127, le=20)
    max_devices: int = Field(default=10000, description="Maximum devices to track", gt=0)

    # Logging settings
    log_level: str = Field(default="INFO", description="Logging level")
    log_file: Optional[str] = Field(None, description="Log file path")

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v):
        """Validate log level."""
        valid_levels = ["TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of: {', '.join(valid_levels)}")
        return v.upper()


# Device detection constants
class DeviceConstants:
    """Constants used for device detection."""

    # Service UUIDs
    TILE_SERVICE_UUID = 65261

    # Company IDs
    APPLE_COMPANY_ID = 76
    MICROSOFT_COMPANY_ID = 6
    GOOGLE_COMPANY_ID = 224
    SAMSUNG_COMPANY_ID = 117

    # Apple device signatures
    APPLE_SIGNATURES = {
        "0719": DeviceType.AIRTAG_UNREGISTERED,
        "121900": DeviceType.APPLE_UNKNOWN,
        "121910": DeviceType.AIRTAG_REGISTERED,
        "121918": DeviceType.AIRPODS,
        "121950": DeviceType.APPLE_UNKNOWN,
    }

    # RSSI quality thresholds
    RSSI_EXCELLENT = -30
    RSSI_GOOD = -50
    RSSI_FAIR = -70
    RSSI_POOR = -80
