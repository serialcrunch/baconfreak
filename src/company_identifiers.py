"""
Company identifiers management using Pydantic and enhanced error handling.
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

from .config import config

# Database connection
db = SqliteDatabase(None)


class CompanyIdentifier(Model):
    """Pydantic-enhanced model for storing company identifier information."""

    company_id = IntegerField(index=True, unique=True)
    name = CharField(max_length=255)

    class Meta:
        database = db
        table_name = "company_identifiers"
        indexes = ((("company_id",), True),)  # Unique index


class LastUpdate(Model):
    """Model for tracking last update timestamp."""

    id = IntegerField(primary_key=True, default=1)
    timestamp = TextField()
    record_count = IntegerField(default=0)

    class Meta:
        database = db
        table_name = "last_update"


class CompanyRecord(BaseModel):
    """Pydantic model for validating company identifier records."""

    model_config = {"validate_assignment": True}

    value: int = Field(..., description="Company identifier value", ge=0, le=65535)
    name: str = Field(..., description="Company name", min_length=1, max_length=255)

    @field_validator("name")
    @classmethod
    def clean_name(cls, v):
        """Clean and validate company name."""
        return v.strip()


class CompanyDatabase(BaseModel):
    """Pydantic model for validating company identifier database files."""

    model_config = {"validate_assignment": True}

    company_identifiers: List[CompanyRecord] = Field(
        ..., description="List of company identifier records", min_length=1
    )

    @field_validator("company_identifiers")
    @classmethod
    def unique_company_ids(cls, v):
        """Ensure company IDs are unique."""
        seen_ids = set()
        for record in v:
            if record.value in seen_ids:
                raise ValueError(f"Duplicate company ID: {record.value}")
            seen_ids.add(record.value)
        return v


class CompanyIdentifiers:
    """Company identifiers manager with enhanced validation and error handling."""

    def __init__(self):
        self.logger = logger.bind(component="company_identifiers")
        self.db_path = config.company_identifiers_db_path
        self.source_paths = config.company_identifiers_sources

        # Performance caching
        self._cache: Dict[int, Optional[List[str]]] = {}
        self._cache_enabled = True

        # Statistics
        self.stats = {
            "lookups": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "records_loaded": 0,
            "last_update": None,
        }

        self._db_connect()

    def _db_connect(self):
        """Initialize database connection with error handling."""
        try:
            # Ensure database directory exists
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

            # Initialize database
            db.init(str(self.db_path))
            db.connect()
            db.create_tables([CompanyIdentifier, LastUpdate], safe=True)

            self.logger.info(f"Connected to database: {self.db_path}")

            # Load initial statistics
            self._load_stats()

            # Auto-populate database on first run if empty
            if CompanyIdentifier.select().count() == 0:
                self.logger.info("Database is empty, auto-populating from YAML sources...")
                try:
                    self.update()
                except Exception as e:
                    self.logger.warning(f"Failed to auto-populate database: {e}")

        except Exception as e:
            self.logger.error(f"Failed to connect to database: {e}")
            raise

    def _load_stats(self):
        """Load statistics from database."""
        try:
            last_update = LastUpdate.get_by_id(1)
            self.stats["last_update"] = last_update.timestamp
            self.stats["records_loaded"] = last_update.record_count
        except DoesNotExist:
            self.logger.debug("No previous update record found")

    def update(self, force: bool = False) -> Dict[str, Any]:
        """
        Update company identifiers database with enhanced validation and reporting.

        Args:
            force: Force update even if files haven't changed

        Returns:
            Dictionary with update statistics
        """
        update_stats = {
            "files_processed": 0,
            "records_loaded": 0,
            "records_saved": 0,
            "errors": [],
            "warnings": [],
            "duration": 0,
        }

        start_time = datetime.now()

        try:
            # Get current database state
            try:
                last_update = LastUpdate.get_by_id(1)
                self.logger.info(f"Last update: {last_update.timestamp}")
            except DoesNotExist:
                last_update = LastUpdate.create(id=1, timestamp="Never", record_count=0)
                self.logger.info("Initializing database for first time")

            # Clear existing data with confirmation
            current_count = CompanyIdentifier.select().count()
            self.logger.info(f"Clearing existing {current_count} records...")

            with db.atomic():
                CompanyIdentifier.delete().execute()

            self.logger.info("Database cleared")

            # Load data from source files with validation
            all_records: Dict[int, CompanyRecord] = {}

            for source_path in self.source_paths:
                if not source_path.exists():
                    warning = f"Source file not found: {source_path}"
                    update_stats["warnings"].append(warning)
                    self.logger.warning(warning)
                    continue

                try:
                    file_records = self._load_source_file(source_path)
                    update_stats["files_processed"] += 1
                    update_stats["records_loaded"] += len(file_records)

                    # Merge records, with later files overriding earlier ones
                    for record in file_records:
                        if record.value in all_records:
                            self.logger.debug(
                                f"Overriding company ID {record.value}: "
                                f"{all_records[record.value].name} -> {record.name}"
                            )
                        all_records[record.value] = record

                    self.logger.info(f"Loaded {len(file_records)} records from {source_path.name}")

                except Exception as e:
                    error = f"Error loading {source_path}: {e}"
                    update_stats["errors"].append(error)
                    self.logger.error(error)
                    continue

            if not all_records:
                raise ValueError("No company identifiers loaded from any source file")

            # Save to database with transaction safety
            self.logger.info(f"Saving {len(all_records)} company identifier records...")
            batch_size = config.db_batch_size

            with db.atomic():
                # Convert to Peewee models
                db_records = [
                    CompanyIdentifier(company_id=record.value, name=record.name)
                    for record in all_records.values()
                ]

                # Bulk create with progress tracking
                for i in range(0, len(db_records), batch_size):
                    batch = db_records[i : i + batch_size]
                    CompanyIdentifier.bulk_create(batch, batch_size)
                    self.logger.debug(f"Saved batch {i//batch_size + 1}")

                # Update metadata
                last_update.timestamp = datetime.now().isoformat(timespec="seconds")
                last_update.record_count = len(all_records)
                last_update.save()

            update_stats["records_saved"] = len(all_records)

            # Clear cache after update
            self._clear_cache()

            # Update internal stats
            self.stats["records_loaded"] = len(all_records)
            self.stats["last_update"] = last_update.timestamp

            update_stats["duration"] = (datetime.now() - start_time).total_seconds()

            self.logger.success(
                f"Successfully updated {len(all_records)} company identifier records "
                f"in {update_stats['duration']:.2f} seconds"
            )

            return update_stats

        except Exception as e:
            error = f"Failed to update company identifiers: {e}"
            update_stats["errors"].append(error)
            self.logger.error(error)
            raise

    def _load_source_file(self, source_path: Path) -> List[CompanyRecord]:
        """
        Load and validate a single source file.

        Args:
            source_path: Path to YAML source file

        Returns:
            List of validated CompanyRecord objects
        """
        try:
            # Load YAML with safe loader
            with source_path.open("r", encoding="utf-8") as f:
                raw_data = yaml.safe_load(f)

            if not raw_data:
                raise ValueError("File is empty or invalid")

            # Validate structure with Pydantic
            company_db = CompanyDatabase(**raw_data)

            return company_db.company_identifiers

        except yaml.YAMLError as e:
            raise ValueError(f"YAML parsing error: {e}")
        except Exception as e:
            raise ValueError(f"File validation error: {e}")

    def lookup(self, company_id: int) -> Optional[List[str]]:
        """
        Look up company name with caching and enhanced error handling.

        Args:
            company_id: Integer company identifier

        Returns:
            List of company names or None if not found
        """
        if not isinstance(company_id, int):
            raise ValueError("Company identifier must be an integer")

        if not 0 <= company_id <= 65535:
            raise ValueError("Company identifier must be between 0 and 65535")

        self.stats["lookups"] += 1

        # Check cache first
        if self._cache_enabled and company_id in self._cache:
            self.stats["cache_hits"] += 1
            result = self._cache[company_id]
            self.logger.debug(f"Cache hit for company ID {company_id}")
            return result

        self.stats["cache_misses"] += 1

        try:
            # Database lookup
            results = CompanyIdentifier.select(CompanyIdentifier.name).where(
                CompanyIdentifier.company_id == company_id
            )

            names = [result.name for result in results]
            result = names if names else None

            # Update cache
            if self._cache_enabled:
                self._cache[company_id] = result

            if result:
                self.logger.debug(f"Company {company_id} resolved to: {result[0]}")
            else:
                self.logger.debug(f"Unknown company ID: {company_id}")

            return result

        except Exception as e:
            self.logger.error(f"Database lookup error for company ID {company_id}: {e}")
            return None

    def bulk_lookup(self, company_ids: List[int]) -> Dict[int, Optional[List[str]]]:
        """
        Perform bulk lookup for multiple company IDs.

        Args:
            company_ids: List of company identifiers

        Returns:
            Dictionary mapping company IDs to company names
        """
        results = {}

        # Separate cached and uncached IDs
        uncached_ids = []
        for cid in company_ids:
            if self._cache_enabled and cid in self._cache:
                results[cid] = self._cache[cid]
                self.stats["cache_hits"] += 1
            else:
                uncached_ids.append(cid)
                self.stats["cache_misses"] += 1

        # Bulk database lookup for uncached IDs
        if uncached_ids:
            try:
                db_results = CompanyIdentifier.select().where(
                    CompanyIdentifier.company_id.in_(uncached_ids)
                )

                # Process results
                found_ids = set()
                for result in db_results:
                    cid = result.company_id
                    names = [result.name]
                    results[cid] = names
                    found_ids.add(cid)

                    # Update cache
                    if self._cache_enabled:
                        self._cache[cid] = names

                # Mark unfound IDs as None
                for cid in uncached_ids:
                    if cid not in found_ids:
                        results[cid] = None
                        if self._cache_enabled:
                            self._cache[cid] = None

            except Exception as e:
                self.logger.error(f"Bulk lookup error: {e}")
                # Fill remaining with None
                for cid in uncached_ids:
                    if cid not in results:
                        results[cid] = None

        self.stats["lookups"] += len(company_ids)
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics."""
        try:
            total_records = CompanyIdentifier.select().count()
        except:
            total_records = 0

        cache_hit_rate = (
            self.stats["cache_hits"] / max(self.stats["lookups"], 1)
            if self.stats["lookups"] > 0
            else 0
        )

        return {
            "database_records": total_records,
            "cache_size": len(self._cache),
            "cache_hit_rate": round(cache_hit_rate, 3),
            "last_update": self.stats["last_update"],
            **self.stats,
        }

    def _clear_cache(self):
        """Clear the lookup cache."""
        self._cache.clear()
        self.logger.debug("Cache cleared")

    def enable_cache(self, enabled: bool = True):
        """Enable or disable caching."""
        self._cache_enabled = enabled
        if not enabled:
            self._clear_cache()
        self.logger.info(f"Cache {'enabled' if enabled else 'disabled'}")

    def close(self):
        """Close database connection and log final statistics."""
        stats = self.get_statistics()
        self.logger.info(
            f"Company identifier service closing - "
            f"Lookups: {stats['lookups']}, "
            f"Cache hit rate: {stats['cache_hit_rate']:.1%}"
        )

        if not db.is_closed():
            db.close()
            self.logger.debug("Database connection closed")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
