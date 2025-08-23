"""
OUI (Organizationally Unique Identifier) management for WiFi MAC address vendor lookup.

This module provides functionality to lookup WiFi device vendors based on MAC address OUI
using IEEE OUI database. Similar to BLE company identifiers but for WiFi MAC addresses.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from loguru import logger
from peewee import (
    CharField,
    DoesNotExist,
    IntegerField,
    Model,
    SchemaManager,
    SqliteDatabase,
    TextField,
)
from pydantic import BaseModel, Field, field_validator

from ...config import config

# Database connection
db = SqliteDatabase(None)


class OUIIdentifier(Model):
    """Model for storing OUI identifier information."""

    oui = CharField(index=True, unique=True, max_length=8)  # e.g., "00:11:22"
    vendor_name = CharField(max_length=255)
    
    class Meta:
        database = db
        table_name = "oui_identifiers"
        indexes = ((("oui",), True),)  # Unique index


class LastOUIUpdate(Model):
    """Model for tracking last OUI update timestamp."""

    id = IntegerField(primary_key=True, default=1)
    timestamp = TextField()
    record_count = IntegerField(default=0)

    class Meta:
        database = db
        table_name = "last_oui_update"


class OUIRecord(BaseModel):
    """Pydantic model for validating OUI records."""

    model_config = {"validate_assignment": True}

    oui: str = Field(..., description="OUI value (first 3 bytes of MAC)", min_length=8, max_length=8)
    vendor_name: str = Field(..., description="Vendor/manufacturer name", min_length=1, max_length=255)

    @field_validator("oui")
    @classmethod
    def validate_oui_format(cls, v):
        """Validate OUI format (XX:XX:XX)."""
        v = v.upper().strip()
        if not v.count(':') == 2:
            raise ValueError("OUI must be in format XX:XX:XX")
        parts = v.split(':')
        if len(parts) != 3:
            raise ValueError("OUI must have exactly 3 parts")
        for part in parts:
            if len(part) != 2:
                raise ValueError("Each OUI part must be exactly 2 characters")
            try:
                int(part, 16)
            except ValueError:
                raise ValueError(f"Invalid hex value in OUI: {part}")
        return v

    @field_validator("vendor_name")
    @classmethod
    def clean_vendor_name(cls, v):
        """Clean and validate vendor name."""
        return v.strip()


class OUIDatabase(BaseModel):
    """Pydantic model for validating OUI database files."""

    model_config = {"validate_assignment": True}

    oui_identifiers: List[OUIRecord] = Field(
        ..., description="List of OUI identifier records", min_length=1
    )

    @field_validator("oui_identifiers")
    @classmethod
    def unique_ouis(cls, v):
        """Ensure OUIs are unique."""
        seen_ouis = set()
        for record in v:
            if record.oui in seen_ouis:
                raise ValueError(f"Duplicate OUI: {record.oui}")
            seen_ouis.add(record.oui)
        return v


class OUIIdentifiers:
    """OUI identifiers manager with enhanced validation and error handling."""

    def __init__(self):
        self.logger = logger.bind(component="oui_identifiers")
        self.db_path = config.oui_identifiers_db_path
        self.source_paths = config.oui_identifiers_sources

        # Performance caching
        self._cache: Dict[str, Optional[str]] = {}
        self._cache_enabled = True

        # Statistics
        self.stats = {
            "lookups_performed": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "database_queries": 0,
            "successful_lookups": 0,
            "failed_lookups": 0,
        }

        # Initialize database
        self._initialize_database()

    def _initialize_database(self) -> None:
        """Initialize the OUI database connection and schema."""
        try:
            # Initialize database connection
            db.init(str(self.db_path))
            
            # Create tables if they don't exist
            with db.atomic():
                db.create_tables([OUIIdentifier, LastOUIUpdate], safe=True)
                
            self.logger.info(f"OUI database initialized at {self.db_path}")
            
            # Check if database needs initial population
            if not self._has_data():
                self.logger.info("Empty OUI database detected, updating from sources")
                self.update_from_sources()
                
        except Exception as e:
            self.logger.error(f"Failed to initialize OUI database: {e}")
            raise

    def _has_data(self) -> bool:
        """Check if the database has any OUI data."""
        try:
            return OUIIdentifier.select().count() > 0
        except Exception:
            return False

    def lookup_vendor(self, mac_address: str) -> Optional[str]:
        """
        Look up vendor name for a given MAC address.
        
        Args:
            mac_address: MAC address in any common format
            
        Returns:
            Vendor name if found, "Randomized" for randomized MACs, None otherwise
        """
        self.stats["lookups_performed"] += 1
        
        try:
            # Extract OUI from MAC address
            oui = self._extract_oui(mac_address)
            if not oui:
                self.stats["failed_lookups"] += 1
                return None
            
            # Check cache first
            if self._cache_enabled and oui in self._cache:
                self.stats["cache_hits"] += 1
                result = self._cache[oui]
                if result:
                    self.stats["successful_lookups"] += 1
                else:
                    self.stats["failed_lookups"] += 1
                return result
            
            # Database lookup
            self.stats["cache_misses"] += 1
            self.stats["database_queries"] += 1
            
            try:
                identifier = OUIIdentifier.get(OUIIdentifier.oui == oui)
                vendor_name = identifier.vendor_name
                
                # Cache result
                if self._cache_enabled:
                    self._cache[oui] = vendor_name
                
                self.stats["successful_lookups"] += 1
                return vendor_name
                
            except DoesNotExist:
                # No database entry found - check if this is a randomized MAC
                if self._is_randomized_mac(mac_address):
                    # Cache the result as "Randomized"
                    if self._cache_enabled:
                        self._cache[oui] = "Randomized"
                    
                    self.stats["successful_lookups"] += 1
                    return "Randomized"
                else:
                    # Cache negative result for global MACs with no entry
                    if self._cache_enabled:
                        self._cache[oui] = None
                    
                    self.stats["failed_lookups"] += 1
                    return None
                
        except Exception as e:
            self.logger.error(f"Error during OUI lookup for {mac_address}: {e}")
            self.stats["failed_lookups"] += 1
            return None

    def _extract_oui(self, mac_address: str) -> Optional[str]:
        """
        Extract OUI (first 3 bytes) from MAC address.
        
        Args:
            mac_address: MAC address in various formats
            
        Returns:
            OUI in XX:XX:XX format or None if invalid
        """
        try:
            # Clean MAC address - remove common separators and normalize
            clean_mac = mac_address.replace(":", "").replace("-", "").replace(" ", "").upper()
            
            # Must be exactly 12 hex characters
            if len(clean_mac) != 12:
                return None
            
            # Validate hex
            int(clean_mac, 16)
            
            # Extract first 6 characters (3 bytes) and format with colons
            oui_bytes = [clean_mac[i:i+2] for i in range(0, 6, 2)]
            return ":".join(oui_bytes)
            
        except ValueError:
            return None

    def _is_randomized_mac(self, mac_address: str) -> bool:
        """
        Check if a MAC address is randomized/locally administered.
        
        A MAC address is considered randomized if:
        1. The locally administered bit (bit 1) in the first octet is set
        2. This indicates the address is not globally unique and likely randomized
        
        Args:
            mac_address: MAC address in any common format
            
        Returns:
            True if MAC appears to be randomized, False otherwise
        """
        try:
            # Clean and extract first octet
            clean_mac = mac_address.replace(":", "").replace("-", "").replace(" ", "").upper()
            
            if len(clean_mac) < 2:
                return False
                
            # Get first octet (first 2 hex characters)
            first_octet = int(clean_mac[:2], 16)
            
            # Check if locally administered bit (bit 1) is set
            # In binary: xxxx xx1x (bit 1 from right, 0-indexed)
            locally_administered = (first_octet & 0x02) != 0
            
            return locally_administered
            
        except ValueError:
            return False

    def bulk_lookup(self, mac_addresses: List[str]) -> Dict[str, Optional[str]]:
        """
        Perform bulk lookup for multiple MAC addresses.
        
        Args:
            mac_addresses: List of MAC addresses
            
        Returns:
            Dictionary mapping MAC addresses to vendor names
        """
        results = {}
        for mac in mac_addresses:
            results[mac] = self.lookup_vendor(mac)
        return results

    def update_from_sources(self) -> None:
        """Update OUI database from configured YAML sources."""
        try:
            self.logger.info("Starting OUI database update from sources")
            
            total_records = 0
            for source_path in self.source_paths:
                if not source_path.exists():
                    self.logger.warning(f"OUI source file not found: {source_path}")
                    continue
                    
                self.logger.info(f"Loading OUI data from {source_path}")
                records = self._load_yaml_source(source_path)
                total_records += len(records)
                
            # Update last update timestamp
            try:
                last_update, created = LastOUIUpdate.get_or_create(id=1)
                last_update.timestamp = datetime.now().isoformat()
                last_update.record_count = total_records
                last_update.save()
            except Exception as e:
                self.logger.error(f"Failed to update timestamp: {e}")
                
            # Clear cache after update
            self._cache.clear()
            
            self.logger.info(f"OUI database updated successfully with {total_records} records")
            
        except Exception as e:
            self.logger.error(f"Failed to update OUI database: {e}")
            raise

    def _load_yaml_source(self, source_path: Path) -> List[OUIRecord]:
        """Load and validate OUI data from YAML source."""
        try:
            with open(source_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            # Validate with Pydantic
            oui_db = OUIDatabase(**data)
            
            # Update database
            with db.atomic():
                for record in oui_db.oui_identifiers:
                    OUIIdentifier.replace(
                        oui=record.oui,
                        vendor_name=record.vendor_name
                    ).execute()
                    
            return oui_db.oui_identifiers
            
        except Exception as e:
            self.logger.error(f"Failed to load YAML source {source_path}: {e}")
            raise

    def get_statistics(self) -> Dict[str, Any]:
        """Get performance and usage statistics."""
        try:
            db_count = OUIIdentifier.select().count()
            cache_size = len(self._cache)
            
            # Calculate cache hit rate
            total_cache_requests = self.stats["cache_hits"] + self.stats["cache_misses"]
            cache_hit_rate = (
                self.stats["cache_hits"] / total_cache_requests
                if total_cache_requests > 0 else 0
            )
            
            # Calculate success rate
            total_lookups = self.stats["successful_lookups"] + self.stats["failed_lookups"]
            success_rate = (
                self.stats["successful_lookups"] / total_lookups
                if total_lookups > 0 else 0
            )
            
            return {
                "database": {
                    "total_ouis": db_count,
                    "database_path": str(self.db_path),
                    "cache_size": cache_size,
                },
                "performance": {
                    "total_lookups": self.stats["lookups_performed"],
                    "successful_lookups": self.stats["successful_lookups"],
                    "failed_lookups": self.stats["failed_lookups"],
                    "success_rate": success_rate,
                    "cache_hits": self.stats["cache_hits"],
                    "cache_misses": self.stats["cache_misses"],
                    "cache_hit_rate": cache_hit_rate,
                    "database_queries": self.stats["database_queries"],
                },
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return {"error": str(e)}

    def clear_cache(self) -> None:
        """Clear the lookup cache."""
        self._cache.clear()
        self.logger.info("OUI lookup cache cleared")

    def close(self) -> None:
        """Close database connection and cleanup resources."""
        try:
            if db and not db.is_closed():
                db.close()
            self.logger.info("OUI database connection closed")
        except Exception as e:
            self.logger.error(f"Error closing OUI database: {e}")


# Global instance for easy access
oui_identifiers: Optional[OUIIdentifiers] = None


def get_oui_identifiers() -> OUIIdentifiers:
    """Get global OUI identifiers instance."""
    global oui_identifiers
    if oui_identifiers is None:
        oui_identifiers = OUIIdentifiers()
    return oui_identifiers