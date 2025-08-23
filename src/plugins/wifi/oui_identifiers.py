"""
WiFi OUI Identifiers using unified database.

This module provides a compatibility wrapper around the unified database
for WiFi OUI identifier lookups. Maintains the same API as the original
oui_identifiers.py but uses the consolidated database.
"""

from typing import Any, Dict, List, Optional

from loguru import logger

from ...database import get_unified_database


class OUIIdentifiers:
    """
    WiFi OUI identifiers manager using unified database.
    
    Provides backward compatibility with the original OUIIdentifiers API
    while using the consolidated database backend.
    """

    def __init__(self):
        self.logger = logger.bind(component="wifi_oui_identifiers")
        self.unified_db = get_unified_database()

    def lookup_vendor(self, mac_address: str) -> Optional[str]:
        """
        Look up vendor name for a given MAC address.
        
        Args:
            mac_address: MAC address in any common format
            
        Returns:
            Vendor name if found, "Randomized" for randomized MACs, None otherwise
        """
        try:
            return self.unified_db.lookup_oui(mac_address)
        except Exception as e:
            self.logger.error(f"OUI lookup failed for {mac_address}: {e}")
            return None

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
            self.unified_db.update_ouis()
            self.logger.info("OUI identifiers updated from unified database")
        except Exception as e:
            self.logger.error(f"OUI identifiers update failed: {e}")
            raise

    def get_statistics(self) -> Dict[str, Any]:
        """Get OUI identifiers statistics."""
        try:
            unified_stats = self.unified_db.get_statistics()
            
            # Extract OUI-specific stats for backward compatibility
            return {
                "database": {
                    "total_ouis": unified_stats["database"]["oui_identifiers"],
                    "database_path": unified_stats["database"]["path"],
                    "cache_size": unified_stats["database"]["oui_cache_size"],
                },
                "performance": {
                    "total_lookups": unified_stats["performance"]["oui_lookups"],
                    "successful_lookups": unified_stats["performance"]["successful_lookups"],
                    "failed_lookups": unified_stats["performance"]["failed_lookups"],
                    "success_rate": unified_stats["performance"]["success_rate"],
                    "cache_hits": unified_stats["performance"]["oui_lookups"] * unified_stats["performance"]["oui_cache_hit_rate"],
                    "cache_misses": unified_stats["performance"]["oui_lookups"] * (1 - unified_stats["performance"]["oui_cache_hit_rate"]),
                    "cache_hit_rate": unified_stats["performance"]["oui_cache_hit_rate"],
                    "database_queries": unified_stats["performance"]["oui_lookups"] * (1 - unified_stats["performance"]["oui_cache_hit_rate"]),
                },
            }
        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return {"error": str(e)}

    def clear_cache(self) -> None:
        """Clear the OUI lookup cache."""
        self.unified_db.clear_cache()

    def close(self) -> None:
        """Close database resources (delegated to unified database)."""
        # Note: Don't close unified DB here as it may be used by other components
        pass


# Global instance for backward compatibility
oui_identifiers: Optional[OUIIdentifiers] = None


def get_oui_identifiers() -> OUIIdentifiers:
    """Get global OUI identifiers instance."""
    global oui_identifiers
    if oui_identifiers is None:
        oui_identifiers = OUIIdentifiers()
    return oui_identifiers