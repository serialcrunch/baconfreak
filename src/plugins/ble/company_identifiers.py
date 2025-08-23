"""
BLE Company Identifiers using unified database.

This module provides a compatibility wrapper around the unified database
for BLE company identifier lookups. Maintains the same API as the original
company_identifiers.py but uses the consolidated database.
"""

from typing import Any, Dict, List, Optional

from loguru import logger

from ...database import get_unified_database


class CompanyIdentifiers:
    """
    BLE Company identifiers manager using unified database.
    
    Provides backward compatibility with the original CompanyIdentifiers API
    while using the consolidated database backend.
    """

    def __init__(self):
        self.logger = logger.bind(component="ble_company_identifiers")
        self.unified_db = get_unified_database()

    def lookup(self, company_id: int) -> Optional[List[str]]:
        """
        Look up company name by Bluetooth SIG company identifier.
        
        Args:
            company_id: Integer company identifier (0-65535)
            
        Returns:
            List containing company name if found, None otherwise
            (List format maintained for backward compatibility)
        """
        if not isinstance(company_id, int):
            raise ValueError("Company identifier must be an integer")

        if not 0 <= company_id <= 65535:
            raise ValueError("Company identifier must be between 0 and 65535")

        try:
            result = self.unified_db.lookup_company(company_id)
            # Return as list for backward compatibility with original API
            return [result] if result else None
        except Exception as e:
            self.logger.error(f"Company lookup failed for {company_id}: {e}")
            return None

    def bulk_lookup(self, company_ids: List[int]) -> Dict[int, Optional[List[str]]]:
        """
        Perform bulk lookup for multiple company IDs.
        
        Args:
            company_ids: List of company identifiers
            
        Returns:
            Dictionary mapping company IDs to company names (or None)
        """
        results = {}
        for company_id in company_ids:
            results[company_id] = self.lookup(company_id)
        return results

    def update(self, force: bool = False) -> Dict[str, Any]:
        """
        Update company identifiers database.
        
        Args:
            force: Force update (ignored, maintained for compatibility)
            
        Returns:
            Dictionary with update statistics
        """
        try:
            records_updated = self.unified_db.update_companies()
            return {
                "files_processed": len(self.unified_db.company_sources),
                "records_loaded": records_updated,
                "records_saved": records_updated,
                "errors": [],
                "warnings": [],
                "duration": 0,  # Not tracked in unified DB
            }
        except Exception as e:
            self.logger.error(f"Company identifiers update failed: {e}")
            return {
                "files_processed": 0,
                "records_loaded": 0,
                "records_saved": 0,
                "errors": [str(e)],
                "warnings": [],
                "duration": 0,
            }

    def get_statistics(self) -> Dict[str, Any]:
        """Get company identifiers statistics."""
        try:
            unified_stats = self.unified_db.get_statistics()
            
            # Extract company-specific stats for backward compatibility
            return {
                "total_companies": unified_stats["database"]["company_identifiers"],
                "cache_size": unified_stats["database"]["company_cache_size"],
                "lookups": unified_stats["performance"]["company_lookups"],
                "cache_hit_rate": unified_stats["performance"]["company_cache_hit_rate"],
                "last_update": unified_stats["last_updates"]["companies"],
            }
        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return {"error": str(e)}

    def close(self) -> None:
        """Close database resources (delegated to unified database)."""
        # Note: Don't close unified DB here as it may be used by other components
        pass

    def clear_cache(self) -> None:
        """Clear the company lookup cache."""
        self.unified_db.clear_cache()


# Global instance for backward compatibility
company_identifiers: Optional[CompanyIdentifiers] = None


def get_company_identifiers() -> CompanyIdentifiers:
    """Get global company identifiers instance."""
    global company_identifiers
    if company_identifiers is None:
        company_identifiers = CompanyIdentifiers()
    return company_identifiers