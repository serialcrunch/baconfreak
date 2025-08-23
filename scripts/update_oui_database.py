#!/usr/bin/env python3
"""
Script to download and convert IEEE OUI database to baconfreak YAML format.

This script downloads the official IEEE OUI (Organizationally Unique Identifier) 
database and converts it to the YAML format used by baconfreak's WiFi plugin.
"""

import re
import yaml
import requests
from pathlib import Path
from typing import Dict, List, Set
import argparse


class OUIParser:
    """Parser for IEEE OUI database format."""
    
    def __init__(self):
        self.oui_pattern = re.compile(r'^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$')
        
    def parse_oui_file(self, file_path: str) -> List[Dict[str, str]]:
        """
        Parse IEEE OUI database file.
        
        Args:
            file_path: Path to the OUI.txt file
            
        Returns:
            List of OUI records with 'oui' and 'vendor_name' fields
        """
        oui_records = []
        seen_ouis = set()
        
        print(f"🔍 Parsing OUI database: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
        total_lines = len(lines)
        processed = 0
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Show progress
            if line_num % 10000 == 0:
                progress = (line_num / total_lines) * 100
                print(f"📊 Progress: {progress:.1f}% ({line_num}/{total_lines} lines)")
            
            # Look for OUI entries (hex format)
            match = self.oui_pattern.match(line)
            if match:
                oui_hex = match.group(1)  # e.g., "28-6F-B9"
                vendor_name = match.group(2).strip()
                
                # Convert to colon format (our standard)
                oui_colon = oui_hex.replace('-', ':')
                
                # Skip duplicates and private entries
                if oui_colon not in seen_ouis and vendor_name.lower() != 'private':
                    # Clean up vendor name
                    vendor_name = self._clean_vendor_name(vendor_name)
                    
                    if vendor_name:  # Only add if we have a valid vendor name
                        oui_records.append({
                            'oui': oui_colon,
                            'vendor_name': vendor_name
                        })
                        seen_ouis.add(oui_colon)
                        processed += 1
        
        print(f"✅ Processed {processed} unique OUI entries from {total_lines} lines")
        return oui_records
    
    def _clean_vendor_name(self, vendor_name: str) -> str:
        """Clean and normalize vendor names."""
        # Remove common suffixes and clean up
        vendor_name = vendor_name.strip()
        
        # Remove trailing periods
        vendor_name = vendor_name.rstrip('.')
        
        # Truncate very long names at reasonable boundaries
        if len(vendor_name) > 50:
            # Try to truncate at word boundaries
            words = vendor_name.split()
            truncated = ""
            for word in words:
                if len(truncated + " " + word) <= 47:
                    if truncated:
                        truncated += " "
                    truncated += word
                else:
                    break
            if truncated:
                vendor_name = truncated + "..."
            else:
                vendor_name = vendor_name[:47] + "..."
        
        return vendor_name


def download_oui_database(url: str, output_path: str) -> bool:
    """Download the IEEE OUI database."""
    try:
        print(f"⬇️  Downloading OUI database from {url}")
        
        # Add proper headers to avoid being blocked
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/plain, text/html, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Make request with headers and longer timeout
        response = requests.get(url, headers=headers, timeout=60)
        response.raise_for_status()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(response.text)
        
        print(f"✅ Downloaded {len(response.text)} characters to {output_path}")
        return True
        
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 418:
            print(f"❌ IEEE server returned 418 (rate limiting/blocking). Trying alternative approach...")
            return try_alternative_download(url, output_path)
        else:
            print(f"❌ HTTP error downloading OUI database: {e}")
            return False
    except Exception as e:
        print(f"❌ Failed to download OUI database: {e}")
        return False


def try_alternative_download(url: str, output_path: str) -> bool:
    """Try alternative download method with different approach."""
    import time
    
    try:
        print("🔄 Attempting alternative download with delay...")
        time.sleep(5)  # Wait a bit before retrying
        
        # Try with minimal headers
        headers = {
            'User-Agent': 'curl/7.68.0',
            'Accept': '*/*'
        }
        
        response = requests.get(url, headers=headers, timeout=90)
        response.raise_for_status()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(response.text)
        
        print(f"✅ Successfully downloaded via alternative method: {len(response.text)} characters")
        return True
        
    except Exception as e:
        print(f"❌ Alternative download also failed: {e}")
        print("💡 You may need to manually download the file from:")
        print(f"   {url}")
        print(f"   and save it as: {output_path}")
        return False


def create_yaml_database(oui_records: List[Dict[str, str]], output_path: str) -> None:
    """Create YAML database file compatible with baconfreak."""
    
    # Sort by OUI for consistent output
    oui_records.sort(key=lambda x: x['oui'])
    
    yaml_data = {
        'oui_identifiers': oui_records
    }
    
    print(f"📝 Writing {len(oui_records)} OUI records to {output_path}")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        # Add header comment
        f.write(f"""# IEEE OUI (Organizationally Unique Identifier) Database
# Generated from: https://standards-oui.ieee.org/oui/oui.txt
# Total entries: {len(oui_records)}
# 
# This file contains MAC address prefixes (OUIs) and their assigned vendors.
# Used by baconfreak WiFi plugin for device vendor identification.

""")
        yaml.dump(yaml_data, f, default_flow_style=False, allow_unicode=True, width=100)
    
    print(f"✅ Created YAML database with {len(oui_records)} entries")


def print_statistics(oui_records: List[Dict[str, str]]) -> None:
    """Print statistics about the OUI database."""
    print(f"\n📊 OUI Database Statistics:")
    print(f"   Total OUI entries: {len(oui_records)}")
    
    # Count entries by first octet (to see distribution)
    first_octet_count = {}
    vendor_count = {}
    
    for record in oui_records:
        first_octet = record['oui'][:2]
        first_octet_count[first_octet] = first_octet_count.get(first_octet, 0) + 1
        
        vendor = record['vendor_name']
        vendor_count[vendor] = vendor_count.get(vendor, 0) + 1
    
    # Top 10 first octets
    print(f"   Top first octets:")
    sorted_octets = sorted(first_octet_count.items(), key=lambda x: x[1], reverse=True)
    for octet, count in sorted_octets[:5]:
        print(f"     {octet}:XX:XX - {count} entries")
    
    # Top vendors (companies with most OUIs)
    print(f"   Top vendors by OUI count:")
    sorted_vendors = sorted(vendor_count.items(), key=lambda x: x[1], reverse=True)
    for vendor, count in sorted_vendors[:10]:
        if count > 1:
            print(f"     {vendor[:40]:<40} - {count} OUIs")


def main():
    """Main script entry point."""
    parser = argparse.ArgumentParser(description='Update OUI database from IEEE')
    parser.add_argument('--url', default='https://standards-oui.ieee.org/oui/oui.txt',
                       help='URL to download OUI database from')
    parser.add_argument('--output', default='external/ieee_oui_identifiers.yaml',
                       help='Output YAML file path')
    parser.add_argument('--temp-txt', default='/tmp/ieee_oui.txt',
                       help='Temporary file for downloaded OUI.txt')
    parser.add_argument('--download', action='store_true',
                       help='Download fresh data (otherwise use existing temp file)')
    
    args = parser.parse_args()
    
    # Ensure output directory exists
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Download if requested or file doesn't exist
    temp_txt_path = Path(args.temp_txt)
    if args.download or not temp_txt_path.exists():
        if not download_oui_database(args.url, args.temp_txt):
            return 1
    
    # Parse the OUI database
    parser = OUIParser()
    oui_records = parser.parse_oui_file(args.temp_txt)
    
    if not oui_records:
        print("❌ No OUI records found!")
        return 1
    
    # Create YAML database
    create_yaml_database(oui_records, args.output)
    
    # Print statistics
    print_statistics(oui_records)
    
    print(f"\n🎉 Successfully created OUI database: {args.output}")
    print(f"💡 You can now update baconfreak configuration to use this file")
    
    return 0


if __name__ == '__main__':
    exit(main())