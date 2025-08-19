#!/usr/bin/env python3
"""
Test script for company identifier lookups.
Run with: python tests/unit/test_company_lookup.py
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.company_identifiers import CompanyIdentifiers

def test_lookups():
    """Test various company ID lookups."""
    print("🧪 Testing Company Identifier Lookups")
    print("=" * 50)
    
    ci = CompanyIdentifiers()
    
    # Test cases: (company_id, expected_company_name_part)
    test_cases = [
        (76, "Apple"),           # Apple Inc.
        (224, "Google"),         # Google
        (6, "Microsoft"),        # Microsoft Corporation
        (15, "Broadcom"),        # Broadcom Corporation
        (999, None),             # Unknown company
        (12345, None),           # Unknown company
    ]
    
    print(f"Database stats: {ci.stats}")
    print()
    
    for company_id, expected in test_cases:
        result = ci.lookup(company_id)
        
        if result:
            company_name = result[0]
            status = "✅" if expected and expected.lower() in company_name.lower() else "⚠️"
            print(f"{status} Company ID {company_id:>5}: {company_name}")
        else:
            status = "✅" if expected is None else "❌"
            print(f"{status} Company ID {company_id:>5}: Unknown")
    
    print()
    print(f"Final stats: {ci.stats}")
    
    # Check if database has data
    total_lookups = ci.stats["lookups"]
    if total_lookups == 0:
        print("\n❌ No lookups performed - database might be empty!")
        print("💡 Run: sudo python main.py update-db")
    elif ci.stats["records_loaded"] == 0:
        print("\n⚠️  Database seems empty or not properly loaded")
        print("💡 Run: sudo python main.py update-db --force")
    else:
        print(f"\n✅ Database working with {ci.stats['records_loaded']} records")

if __name__ == "__main__":
    test_lookups()