"""
Unified database management for baconfreak identifiers.

This module provides a consolidated SQLite database for both:
- Bluetooth SIG Company Identifiers (BLE device manufacturers)
- IEEE OUI Identifiers (WiFi device vendors)

Uses a single database file with separate tables for better performance and maintenance.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from loguru import logger
from peewee import (
    CharField,
    DoesNotExist,
    IntegerField,
    Model,
    SqliteDatabase,
    TextField,
)
from pydantic import BaseModel, Field, field_validator

from .config import config

# Unified database connection
db = SqliteDatabase(None)


class CompanyIdentifier(Model):
    """Model for Bluetooth SIG company identifiers."""

    company_id = IntegerField(index=True, unique=True)
    name = CharField(max_length=255)

    class Meta:
        database = db
        table_name = "company_identifiers"
        indexes = ((("company_id",), True),)


class OUIIdentifier(Model):
    """Model for IEEE OUI identifiers."""

    oui = CharField(index=True, unique=True, max_length=8)  # e.g., "00:11:22"
    vendor_name = CharField(max_length=255)

    class Meta:
        database = db
        table_name = "oui_identifiers"
        indexes = ((("oui",), True),)


class LastUpdate(Model):
    """Model for tracking database update timestamps."""

    id = IntegerField(primary_key=True, default=1)
    company_timestamp = TextField(null=True)
    company_record_count = IntegerField(default=0)
    oui_timestamp = TextField(null=True)
    oui_record_count = IntegerField(default=0)

    class Meta:
        database = db
        table_name = "last_update"


# Pydantic validation models
class CompanyRecord(BaseModel):
    """Pydantic model for company identifier records."""

    model_config = {"validate_assignment": True}

    value: int = Field(..., description="Company identifier value", ge=0, le=65535)
    name: str = Field(..., description="Company name", min_length=1, max_length=255)

    @field_validator("name")
    @classmethod
    def clean_name(cls, v):
        return v.strip()


class OUIRecord(BaseModel):
    """Pydantic model for OUI identifier records."""

    model_config = {"validate_assignment": True}

    oui: str = Field(..., description="OUI value (first 3 bytes of MAC)", min_length=8, max_length=8)
    vendor_name: str = Field(..., description="Vendor/manufacturer name", min_length=1, max_length=255)

    @field_validator("oui")
    @classmethod
    def validate_oui_format(cls, v):
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
        return v.strip()


class CompanyDatabase(BaseModel):
    """Pydantic model for company identifier database files."""

    model_config = {"validate_assignment": True}

    company_identifiers: List[CompanyRecord] = Field(
        ..., description="List of company identifier records", min_length=1
    )

    @field_validator("company_identifiers")
    @classmethod
    def unique_company_ids(cls, v):
        seen_ids = set()
        for record in v:
            if record.value in seen_ids:
                raise ValueError(f"Duplicate company ID: {record.value}")
            seen_ids.add(record.value)
        return v


class OUIDatabase(BaseModel):
    """Pydantic model for OUI database files."""

    model_config = {"validate_assignment": True}

    oui_identifiers: List[OUIRecord] = Field(
        ..., description="List of OUI identifier records", min_length=1
    )

    @field_validator("oui_identifiers")
    @classmethod
    def unique_ouis(cls, v):
        seen_ouis = set()
        for record in v:
            if record.oui in seen_ouis:
                raise ValueError(f"Duplicate OUI: {record.oui}")
            seen_ouis.add(record.oui)
        return v


class UnifiedIdentifierDatabase:
    """Unified database manager for both company and OUI identifiers."""

    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize unified database.
        
        Args:
            db_path: Optional custom database path. Uses config default if None.
        """
        self.logger = logger.bind(component="unified_db")
        
        # Use unified database path
        if db_path:
            self.db_path = db_path
        else:
            # Use assets directory with unified database name
            self.db_path = config.assets_dir_path / "identifiers.db"
        
        # Source paths from config
        self.company_sources = config.company_identifiers_sources
        self.oui_sources = config.oui_identifiers_sources

        # Performance caching
        self._company_cache: Dict[int, Optional[str]] = {}
        self._oui_cache: Dict[str, Optional[str]] = {}
        self._cache_enabled = True

        # Statistics
        self.stats = {
            "company_lookups": 0,
            "company_cache_hits": 0,
            "company_cache_misses": 0,
            "oui_lookups": 0,
            "oui_cache_hits": 0,
            "oui_cache_misses": 0,
            "successful_lookups": 0,
            "failed_lookups": 0,
        }

        self._initialize_database()

    def _initialize_database(self) -> None:
        """Initialize the unified database connection and schema."""
        try:
            # Ensure database directory exists with proper permissions
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Initialize database connection
            db.init(str(self.db_path))
            
            # Create tables if they don't exist
            with db.atomic():
                db.create_tables([CompanyIdentifier, OUIIdentifier, LastUpdate], safe=True)
                
            self.logger.info(f"Unified database initialized at {self.db_path}")
            
            # Check if database needs initial population
            company_count = CompanyIdentifier.select().count()
            oui_count = OUIIdentifier.select().count()
            
            if company_count == 0:
                self.logger.info("Empty company database detected, updating from sources")
                self.update_companies()
                
            if oui_count == 0:
                self.logger.info("Empty OUI database detected, updating from sources")
                self.update_ouis()
                
        except Exception as e:
            self.logger.error(f"Failed to initialize unified database: {e}")
            raise

    def lookup_company(self, company_id: int) -> Optional[str]:
        """
        Look up company name by Bluetooth SIG company identifier.
        
        Args:
            company_id: Bluetooth company identifier (0-65535)
            
        Returns:
            Company name if found, None otherwise
        """
        self.stats["company_lookups"] += 1
        
        try:
            # Check cache first
            if self._cache_enabled and company_id in self._company_cache:
                self.stats["company_cache_hits"] += 1
                result = self._company_cache[company_id]
                if result:
                    self.stats["successful_lookups"] += 1
                else:
                    self.stats["failed_lookups"] += 1
                return result
            
            # Database lookup
            self.stats["company_cache_misses"] += 1
            
            try:
                identifier = CompanyIdentifier.get(CompanyIdentifier.company_id == company_id)
                company_name = identifier.name
                
                # Cache result
                if self._cache_enabled:
                    self._company_cache[company_id] = company_name
                
                self.stats["successful_lookups"] += 1
                return company_name
                
            except DoesNotExist:
                # Cache negative result
                if self._cache_enabled:
                    self._company_cache[company_id] = None
                
                self.stats["failed_lookups"] += 1
                return None
                
        except Exception as e:
            self.logger.error(f"Error during company lookup for {company_id}: {e}")
            self.stats["failed_lookups"] += 1
            return None

    def lookup_oui(self, mac_address: str) -> Optional[str]:
        """
        Look up vendor name by MAC address OUI.
        
        Args:
            mac_address: MAC address in any common format
            
        Returns:
            Vendor name if found, "Randomized" for randomized MACs, None otherwise
        """
        self.stats["oui_lookups"] += 1
        
        try:
            # Extract OUI from MAC address
            oui = self._extract_oui(mac_address)
            if not oui:
                self.stats["failed_lookups"] += 1
                return None
            
            # Check cache first
            if self._cache_enabled and oui in self._oui_cache:
                self.stats["oui_cache_hits"] += 1
                result = self._oui_cache[oui]
                if result:
                    self.stats["successful_lookups"] += 1
                else:
                    self.stats["failed_lookups"] += 1
                return result
            
            # Database lookup
            self.stats["oui_cache_misses"] += 1
            
            try:
                identifier = OUIIdentifier.get(OUIIdentifier.oui == oui)
                vendor_name = identifier.vendor_name
                
                # Cache result
                if self._cache_enabled:
                    self._oui_cache[oui] = vendor_name
                
                self.stats["successful_lookups"] += 1
                return vendor_name
                
            except DoesNotExist:
                # No database entry found - check if this is a randomized MAC
                if self._is_randomized_mac(mac_address):
                    # Cache the result as "Randomized"
                    if self._cache_enabled:
                        self._oui_cache[oui] = "Randomized"
                    
                    self.stats["successful_lookups"] += 1
                    return "Randomized"
                else:
                    # Cache negative result for global MACs with no entry
                    if self._cache_enabled:
                        self._oui_cache[oui] = None
                    
                    self.stats["failed_lookups"] += 1
                    return None
                
        except Exception as e:
            self.logger.error(f"Error during OUI lookup for {mac_address}: {e}")
            self.stats["failed_lookups"] += 1
            return None

    def _extract_oui(self, mac_address: str) -> Optional[str]:
        """Extract OUI (first 3 bytes) from MAC address."""
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
        """Check if a MAC address is randomized/locally administered."""
        try:
            # Clean and extract first octet
            clean_mac = mac_address.replace(":", "").replace("-", "").replace(" ", "").upper()
            
            if len(clean_mac) < 2:
                return False
                
            # Get first octet (first 2 hex characters)
            first_octet = int(clean_mac[:2], 16)
            
            # Check if locally administered bit (bit 1) is set
            locally_administered = (first_octet & 0x02) != 0
            
            return locally_administered
            
        except ValueError:
            return False

    def update_companies(self) -> int:
        """Update company identifiers from YAML sources."""
        try:
            self.logger.info("Starting company identifiers update from sources")
            
            total_records = 0
            for source_path in self.company_sources:
                if not source_path.exists():
                    self.logger.warning(f"Company source file not found: {source_path}")
                    continue
                    
                self.logger.info(f"Loading company data from {source_path}")
                records = self._load_company_yaml_source(source_path)
                total_records += len(records)
                
            # Update timestamp
            self._update_company_timestamp(total_records)
            
            # Clear cache after update
            self._company_cache.clear()
            
            self.logger.info(f"Company identifiers updated successfully with {total_records} records")
            return total_records
            
        except Exception as e:
            self.logger.error(f"Failed to update company identifiers: {e}")
            raise

    def update_ouis(self) -> int:
        """Update OUI identifiers from YAML sources."""
        try:
            self.logger.info("Starting OUI identifiers update from sources")
            
            total_records = 0
            for source_path in self.oui_sources:
                if not source_path.exists():
                    self.logger.warning(f"OUI source file not found: {source_path}")
                    continue
                    
                self.logger.info(f"Loading OUI data from {source_path}")
                records = self._load_oui_yaml_source(source_path)
                total_records += len(records)
                
            # Update timestamp
            self._update_oui_timestamp(total_records)
            
            # Clear cache after update
            self._oui_cache.clear()
            
            self.logger.info(f"OUI identifiers updated successfully with {total_records} records")
            return total_records
            
        except Exception as e:
            self.logger.error(f"Failed to update OUI identifiers: {e}")
            raise

    def _load_company_yaml_source(self, source_path: Path) -> List[CompanyRecord]:
        """Load and validate company data from YAML source."""
        try:
            with open(source_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            # Validate with Pydantic
            company_db = CompanyDatabase(**data)
            
            # Update database
            with db.atomic():
                for record in company_db.company_identifiers:
                    CompanyIdentifier.replace(
                        company_id=record.value,
                        name=record.name
                    ).execute()
                    
            return company_db.company_identifiers
            
        except Exception as e:
            self.logger.error(f"Failed to load company YAML source {source_path}: {e}")
            raise

    def _load_oui_yaml_source(self, source_path: Path) -> List[OUIRecord]:
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
            self.logger.error(f"Failed to load OUI YAML source {source_path}: {e}")
            raise

    def _update_company_timestamp(self, record_count: int) -> None:
        """Update company identifiers timestamp."""
        try:
            last_update, created = LastUpdate.get_or_create(id=1)
            last_update.company_timestamp = datetime.now().isoformat()
            last_update.company_record_count = record_count
            last_update.save()
        except Exception as e:
            self.logger.error(f"Failed to update company timestamp: {e}")

    def _update_oui_timestamp(self, record_count: int) -> None:
        """Update OUI identifiers timestamp."""
        try:
            last_update, created = LastUpdate.get_or_create(id=1)
            last_update.oui_timestamp = datetime.now().isoformat()
            last_update.oui_record_count = record_count
            last_update.save()
        except Exception as e:
            self.logger.error(f"Failed to update OUI timestamp: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive database statistics."""
        try:
            company_count = CompanyIdentifier.select().count()
            oui_count = OUIIdentifier.select().count()
            
            # Get last update info
            try:
                last_update = LastUpdate.get_by_id(1)
                company_timestamp = last_update.company_timestamp
                oui_timestamp = last_update.oui_timestamp
                company_records = last_update.company_record_count
                oui_records = last_update.oui_record_count
            except DoesNotExist:
                company_timestamp = oui_timestamp = None
                company_records = oui_records = 0
            
            # Calculate cache hit rates
            total_company_requests = self.stats["company_cache_hits"] + self.stats["company_cache_misses"]
            total_oui_requests = self.stats["oui_cache_hits"] + self.stats["oui_cache_misses"]
            
            company_hit_rate = (
                self.stats["company_cache_hits"] / total_company_requests
                if total_company_requests > 0 else 0
            )
            oui_hit_rate = (
                self.stats["oui_cache_hits"] / total_oui_requests
                if total_oui_requests > 0 else 0
            )
            
            # Calculate success rate
            total_lookups = self.stats["successful_lookups"] + self.stats["failed_lookups"]
            success_rate = (
                self.stats["successful_lookups"] / total_lookups
                if total_lookups > 0 else 0
            )
            
            return {
                "database": {
                    "path": str(self.db_path),
                    "company_identifiers": company_count,
                    "oui_identifiers": oui_count,
                    "total_records": company_count + oui_count,
                    "company_cache_size": len(self._company_cache),
                    "oui_cache_size": len(self._oui_cache),
                },
                "last_updates": {
                    "companies": company_timestamp,
                    "ouis": oui_timestamp,
                    "company_records": company_records,
                    "oui_records": oui_records,
                },
                "performance": {
                    "total_lookups": total_lookups,
                    "successful_lookups": self.stats["successful_lookups"],
                    "failed_lookups": self.stats["failed_lookups"],
                    "success_rate": success_rate,
                    "company_lookups": self.stats["company_lookups"],
                    "oui_lookups": self.stats["oui_lookups"],
                    "company_cache_hit_rate": company_hit_rate,
                    "oui_cache_hit_rate": oui_hit_rate,
                },
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return {"error": str(e)}

    def clear_cache(self) -> None:
        """Clear all lookup caches."""
        self._company_cache.clear()
        self._oui_cache.clear()
        self.logger.info("All lookup caches cleared")

    def close(self) -> None:
        """Close database connection and cleanup resources."""
        try:
            if db and not db.is_closed():
                db.close()
            self.logger.info("Unified database connection closed")
        except Exception as e:
            self.logger.error(f"Error closing unified database: {e}")


# Global instance for easy access
unified_db: Optional[UnifiedIdentifierDatabase] = None


def get_unified_database() -> UnifiedIdentifierDatabase:
    """Get global unified database instance."""
    global unified_db
    if unified_db is None:
        unified_db = UnifiedIdentifierDatabase()
    return unified_db