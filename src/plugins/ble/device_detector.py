"""
Device detection logic using Pydantic models and structured logging.
"""

from typing import Dict, List, Optional, Set

from loguru import logger
from scapy.layers.bluetooth import (
    EIR_CompleteLocalName,
    EIR_Manufacturer_Specific_Data,
    EIR_ServiceData16BitUUID,
    EIR_ShortenedLocalName,
    EIR_TX_Power_Level,
    HCI_LE_Meta_Advertising_Report,
)
from scapy.packet import Raw

from ...company_identifiers import CompanyIdentifiers
from ...models import BluetoothDevice, DeviceConstants, DeviceType, PacketInfo


class DeviceDetector:
    """Device detection with enhanced capabilities and Pydantic models."""

    def __init__(self, company_resolver: CompanyIdentifiers):
        self.logger = logger.bind(component="device_detector")
        self.company_resolver = company_resolver

        # Tracking sets for performance
        self._known_companies: Set[str] = set()
        self._unknown_companies: Set[int] = set()

        # Detection statistics
        self.detection_stats = {
            "total_packets": 0,
            "successful_extractions": 0,
            "failed_extractions": 0,
            "devices_created": 0,
        }

    def extract_packet_info(self, report) -> Optional[PacketInfo]:
        """
        Extract comprehensive information from a Bluetooth advertising report.

        Args:
            report: Scapy HCI_LE_Meta_Advertising_Report

        Returns:
            PacketInfo object or None if packet cannot be processed
        """
        self.detection_stats["total_packets"] += 1

        try:
            if not report.haslayer(HCI_LE_Meta_Advertising_Report):
                return None

            adv_report = report[HCI_LE_Meta_Advertising_Report]

            # Extract basic information
            addr = adv_report.addr.lower()  # Normalize to lowercase
            rssi = adv_report.rssi

            # Extract raw data if present
            data = None
            if adv_report.haslayer(Raw):
                data = adv_report[Raw].load.hex()

            # Extract company ID if present
            company_id = None
            if adv_report.haslayer(EIR_Manufacturer_Specific_Data):
                company_id = adv_report[EIR_Manufacturer_Specific_Data].company_id

            # Extract service UUID if present
            service_uuid = None
            if adv_report.haslayer(EIR_ServiceData16BitUUID):
                service_uuid = adv_report[EIR_ServiceData16BitUUID].svc_uuid

            # Extract device name if present
            device_name = None
            if adv_report.haslayer(EIR_CompleteLocalName):
                device_name = adv_report[EIR_CompleteLocalName].local_name.decode(
                    "utf-8", errors="ignore"
                )
            elif adv_report.haslayer(EIR_ShortenedLocalName):
                device_name = adv_report[EIR_ShortenedLocalName].local_name.decode(
                    "utf-8", errors="ignore"
                )

            # Extract TX power if present
            tx_power = None
            if adv_report.haslayer(EIR_TX_Power_Level):
                tx_power = adv_report[EIR_TX_Power_Level].level

            packet_info = PacketInfo(
                addr=addr,
                rssi=rssi,
                data=data,
                company_id=company_id,
                service_uuid=service_uuid,
                device_name=device_name,
                tx_power=tx_power,
                raw_packet=report,
            )

            self.detection_stats["successful_extractions"] += 1
            return packet_info

        except Exception as e:
            self.detection_stats["failed_extractions"] += 1
            self.logger.error(f"Error extracting packet info: {e}")
            return None

    def detect_device_type(self, packet_info: PacketInfo) -> DeviceType:
        """
        Determine device type based on packet information with enhanced detection.

        Args:
            packet_info: PacketInfo object

        Returns:
            DeviceType enum value
        """
        # Check for Tile devices first (most specific)
        if packet_info.service_uuid == DeviceConstants.TILE_SERVICE_UUID:
            self.logger.debug(f"Tile device detected: {packet_info.addr}")
            return DeviceType.TILE

        # Check for Apple devices
        if packet_info.company_id == DeviceConstants.APPLE_COMPANY_ID:
            if packet_info.data:
                apple_type = self._detect_apple_device(packet_info.data, packet_info.addr)
                if apple_type != DeviceType.APPLE_UNKNOWN:
                    return apple_type

        # Check for other known manufacturers with specific patterns
        if packet_info.company_id:
            specific_type = self._detect_by_company_patterns(packet_info)
            if specific_type != DeviceType.UNKNOWN:
                return specific_type

        # Check device name patterns
        if packet_info.device_name:
            name_type = self._detect_by_device_name(packet_info.device_name)
            if name_type != DeviceType.UNKNOWN:
                return name_type

        # Default to unknown
        return DeviceType.UNKNOWN

    def _detect_apple_device(self, data: str, addr: str) -> DeviceType:
        """
        Enhanced Apple device detection with confidence scoring.

        Args:
            data: Hex string of packet data
            addr: Device MAC address for logging

        Returns:
            DeviceType for the Apple device
        """
        if not data or len(data) < 6:
            return DeviceType.APPLE_UNKNOWN

        # Check known Apple signatures
        for signature, device_type in DeviceConstants.APPLE_SIGNATURES.items():
            if data.startswith(signature):
                self.logger.debug(
                    f"Apple device detected: {device_type.value} @ {addr} (signature: {signature})"
                )
                return device_type

        # Additional Apple device detection patterns
        if data.startswith("1219"):  # Apple generic advertisement
            # Try to detect more specific types based on additional data
            if len(data) >= 8:
                subtype = data[6:8]
                if subtype in ["01", "02", "03"]:  # Common AirPods variants
                    return DeviceType.AIRPODS
                elif subtype in ["12", "13", "14"]:  # AirTag variants
                    return DeviceType.AIRTAG_REGISTERED

        return DeviceType.APPLE_UNKNOWN

    def _detect_by_company_patterns(self, packet_info: PacketInfo) -> DeviceType:
        """
        Detect device types based on company-specific patterns.

        Args:
            packet_info: PacketInfo object

        Returns:
            DeviceType based on company patterns
        """
        company_id = packet_info.company_id
        data = packet_info.data or ""

        # Microsoft patterns
        if company_id == DeviceConstants.MICROSOFT_COMPANY_ID:
            if data.startswith("01092022"):  # Xbox Controller pattern
                self.logger.debug(f"Xbox controller detected: {packet_info.addr}")
                # Could add XBOX_CONTROLLER type if needed

        # Samsung patterns
        elif company_id == DeviceConstants.SAMSUNG_COMPANY_ID:
            if packet_info.device_name and "galaxy" in packet_info.device_name.lower():
                self.logger.debug(f"Samsung Galaxy device detected: {packet_info.addr}")

        # Google patterns
        elif company_id == DeviceConstants.GOOGLE_COMPANY_ID:
            if data.startswith("06"):  # Common Google pattern
                self.logger.debug(f"Google device detected: {packet_info.addr}")

        return DeviceType.UNKNOWN

    def _detect_by_device_name(self, device_name: str) -> DeviceType:
        """
        Detect device type based on advertised device name.

        Args:
            device_name: Device name from advertisement

        Returns:
            DeviceType based on name patterns
        """
        name_lower = device_name.lower()

        # AirPods variants
        if any(term in name_lower for term in ["airpods", "airpod"]):
            return DeviceType.AIRPODS

        # Tile variants
        if any(term in name_lower for term in ["tile", "tile mate", "tile slim"]):
            return DeviceType.TILE

        # AirTag (though usually unnamed)
        if "airtag" in name_lower:
            return DeviceType.AIRTAG_REGISTERED

        return DeviceType.UNKNOWN

    def create_device(self, packet_info: PacketInfo) -> BluetoothDevice:
        """
        Create a BluetoothDevice object with enhanced detection and validation.

        Args:
            packet_info: PacketInfo object

        Returns:
            BluetoothDevice object
        """
        device_type = self.detect_device_type(packet_info)

        # Resolve company name with caching
        company_name = None
        if packet_info.company_id is not None:
            company_names = self.company_resolver.lookup(packet_info.company_id)
            if company_names:
                company_name = company_names[0]  # Take first match
                self._known_companies.add(company_name)

                self.logger.bind(
                    company_id=packet_info.company_id, company_name=company_name
                ).debug("Company resolved")
            else:
                self._unknown_companies.add(packet_info.company_id)
                self.logger.bind(company_id=packet_info.company_id).debug("Unknown company ID")

        # Create device with enhanced data
        device = BluetoothDevice(
            addr=packet_info.addr,
            device_type=device_type,
            rssi=packet_info.rssi,
            data=packet_info.data,
            company_id=packet_info.company_id,
            company_name=company_name,
            device_name=packet_info.device_name,
        )

        # Add confidence scoring based on detection method
        device.confidence = self._calculate_confidence(packet_info, device_type)

        # Add automatic tags based on detection
        self._add_automatic_tags(device, packet_info)

        self.detection_stats["devices_created"] += 1

        self.logger.bind(
            addr=device.addr, device_type=device_type.value, confidence=device.confidence
        ).debug("Device created")

        return device

    def _calculate_confidence(self, packet_info: PacketInfo, device_type: DeviceType) -> float:
        """
        Calculate confidence score for device detection.

        Args:
            packet_info: Original packet information
            device_type: Detected device type

        Returns:
            Confidence score between 0.0 and 1.0
        """
        confidence = 0.5  # Base confidence

        # Increase confidence for specific indicators
        if packet_info.service_uuid == DeviceConstants.TILE_SERVICE_UUID:
            confidence = 0.95  # Very high confidence for Tile service UUID

        elif packet_info.company_id == DeviceConstants.APPLE_COMPANY_ID and packet_info.data:
            # Check Apple signature confidence
            for signature in DeviceConstants.APPLE_SIGNATURES:
                if packet_info.data.startswith(signature):
                    confidence = 0.9
                    break
            else:
                confidence = 0.7  # Apple but unknown signature

        elif packet_info.device_name:
            # Increase confidence if device name matches type
            name_lower = packet_info.device_name.lower()
            type_name = device_type.value.lower()
            if any(term in name_lower for term in type_name.split("_")):
                confidence = min(confidence + 0.2, 1.0)

        # Decrease confidence for weak signals
        if packet_info.rssi < -90:
            confidence *= 0.8

        return round(confidence, 2)

    def _add_automatic_tags(self, device: BluetoothDevice, packet_info: PacketInfo):
        """
        Add automatic tags based on device characteristics.

        Args:
            device: BluetoothDevice object to tag
            packet_info: Original packet information
        """
        # Signal strength tags
        if packet_info.rssi > DeviceConstants.RSSI_EXCELLENT:
            device.add_tag("excellent_signal")
        elif packet_info.rssi > DeviceConstants.RSSI_GOOD:
            device.add_tag("good_signal")
        elif packet_info.rssi > DeviceConstants.RSSI_FAIR:
            device.add_tag("fair_signal")
        else:
            device.add_tag("poor_signal")

        # Company tags
        if device.company_name:
            # Normalize company name for tagging
            company_tag = (
                device.company_name.lower().replace(" ", "_").replace(",", "").replace(".", "")
            )
            device.add_tag(f"company_{company_tag}")

        # Device type tags
        if device.device_type != DeviceType.UNKNOWN:
            device.add_tag(f"type_{device.device_type.value}")

        # Special tags for tracking devices
        if device.device_type in [
            DeviceType.AIRTAG_REGISTERED,
            DeviceType.AIRTAG_UNREGISTERED,
            DeviceType.TILE,
        ]:
            device.add_tag("tracker")

        # Apple ecosystem tag
        if (
            device.device_type.value.startswith("airtag")
            or device.device_type == DeviceType.AIRPODS
        ):
            device.add_tag("apple_ecosystem")

    def is_known_company(self, company_id: int) -> bool:
        """
        Check if company ID is known with caching.

        Args:
            company_id: Company identifier

        Returns:
            True if company is known
        """
        # Check cache first
        if any(company_id == cid for cid in self._unknown_companies):
            return False

        # Look up in database
        company_names = self.company_resolver.lookup(company_id)
        is_known = bool(company_names)

        # Update cache
        if is_known:
            self._known_companies.add(company_names[0])
        else:
            self._unknown_companies.add(company_id)

        return is_known

    def get_known_companies(self) -> List[str]:
        """Get list of known companies encountered."""
        return sorted(list(self._known_companies))

    def get_unknown_companies(self) -> List[int]:
        """Get list of unknown company IDs encountered."""
        return sorted(list(self._unknown_companies))

    def get_detection_stats(self) -> Dict[str, int]:
        """Get detection statistics."""
        success_rate = self.detection_stats["successful_extractions"] / max(
            self.detection_stats["total_packets"], 1
        )

        return {**self.detection_stats, "success_rate": round(success_rate, 3)}

    def reset_stats(self):
        """Reset detection statistics."""
        self.detection_stats = {
            "total_packets": 0,
            "successful_extractions": 0,
            "failed_extractions": 0,
            "devices_created": 0,
        }
