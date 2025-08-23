#!/usr/bin/env python3
"""
Script to download and convert Bluetooth SIG company identifiers to baconfreak YAML format.

This script downloads the official Bluetooth SIG company identifiers database 
and converts it to the YAML format used by baconfreak's BLE plugin.
"""

import re
import yaml
import requests
from pathlib import Path
from typing import Dict, List, Set
import argparse


class BluetoothSIGParser:
    """Parser for Bluetooth SIG company identifiers format."""
    
    def __init__(self):
        self.hex_pattern = re.compile(r'^0x[0-9A-Fa-f]+$')
        
    def parse_company_file(self, file_path: str) -> List[Dict[str, any]]:
        """
        Parse Bluetooth SIG company identifiers YAML file.
        
        Args:
            file_path: Path to the company_identifiers.yaml file
            
        Returns:
            List of company records with 'company_id' and 'company_name' fields
        """
        print(f"🔍 Parsing Bluetooth SIG company identifiers: {file_path}")
        
        # Load with robust error handling
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                data = yaml.safe_load(f)
        except yaml.reader.ReaderError as e:
            print(f"⚠️  YAML encoding error, attempting to fix: {e}")
            # Try to clean the file content
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            
            # Additional character replacements for YAML parsing
            additional_replacements = {
                '\ufeff': '',  # BOM character
                '\x00': '',    # Null character
                '\x0b': ' ',   # Vertical tab
                '\x0c': ' ',   # Form feed
            }
            
            for old_char, new_char in additional_replacements.items():
                content = content.replace(old_char, new_char)
            
            # Try parsing the cleaned content
            data = yaml.safe_load(content)
        
        if not data or 'company_identifiers' not in data:
            raise ValueError("Invalid Bluetooth SIG company identifiers format")
        
        company_records = []
        seen_ids = set()
        processed = 0
        
        companies = data['company_identifiers']
        total_companies = len(companies)
        
        print(f"📊 Processing {total_companies} company entries...")
        
        # Process entries with error handling for encoding issues
        for i, entry in enumerate(companies):
            # Show progress
            if (i + 1) % 500 == 0:
                progress = ((i + 1) / total_companies) * 100
                print(f"📈 Progress: {progress:.1f}% ({i + 1}/{total_companies} entries)")
            
            if not isinstance(entry, dict) or 'value' not in entry or 'name' not in entry:
                continue
                
            company_id_hex = entry['value']
            company_name = entry['name'].strip()
            
            # Convert hex string to integer
            if isinstance(company_id_hex, str) and self.hex_pattern.match(company_id_hex):
                company_id = int(company_id_hex, 16)
            elif isinstance(company_id_hex, int):
                company_id = company_id_hex
            else:
                print(f"⚠️  Skipping invalid company ID: {company_id_hex}")
                continue
            
            # Skip duplicates and clean up name
            if company_id not in seen_ids and company_name:
                # Clean up company name
                company_name = self._clean_company_name(company_name)
                
                if company_name:  # Only add if we have a valid company name
                    company_records.append({
                        'value': company_id,
                        'name': company_name
                    })
                    seen_ids.add(company_id)
                    processed += 1
        
        print(f"✅ Processed {processed} unique company identifiers from {total_companies} entries")
        return company_records
    
    def _clean_company_name(self, company_name: str) -> str:
        """Clean and normalize company names."""
        if not company_name:
            return ""
            
        # Remove quotes and extra whitespace
        company_name = company_name.strip('\'"')
        company_name = company_name.strip()
        
        # Fix common encoding artifacts
        encoding_fixes = {
            'AnÃ\x93nima': 'Anónima',  # Fix the specific case we found
            'Ã\x91': 'Ñ',             # Spanish Ñ
            'Ã¡': 'á',                # Spanish á
            'Ã©': 'é',                # Spanish é  
            'Ã­': 'í',                # Spanish í
            'Ã³': 'ó',                # Spanish ó
            'Ã\xba': 'ú',            # Spanish ú
        }
        
        for broken, fixed in encoding_fixes.items():
            company_name = company_name.replace(broken, fixed)
        
        # Remove trailing periods
        company_name = company_name.rstrip('.')
        
        # Remove any remaining problematic characters
        company_name = ''.join(char for char in company_name if ord(char) >= 32 or char.isspace())
        
        # Normalize whitespace
        company_name = ' '.join(company_name.split())
        
        # Truncate very long names at reasonable boundaries
        if len(company_name) > 60:
            # Try to truncate at word boundaries
            words = company_name.split()
            truncated = ""
            for word in words:
                if len(truncated + " " + word) <= 57:
                    if truncated:
                        truncated += " "
                    truncated += word
                else:
                    break
            if truncated:
                company_name = truncated + "..."
            else:
                company_name = company_name[:57] + "..."
        
        return company_name


def download_company_identifiers(url: str, output_path: str) -> bool:
    """Download the Bluetooth SIG company identifiers database."""
    try:
        print(f"⬇️  Downloading Bluetooth SIG company identifiers from {url}")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        # Clean the content to handle encoding issues
        content = response.text
        
        # Fix common encoding issues where Windows-1252 characters got mixed in
        # Replace problematic characters with their proper UTF-8 equivalents
        replacements = {
            '\x80': '€',  # Euro sign
            '\x81': '',   # Unused
            '\x82': '‚',  # Single low-9 quotation mark
            '\x83': 'ƒ',  # Latin small letter f with hook
            '\x84': '„',  # Double low-9 quotation mark
            '\x85': '…',  # Ellipsis
            '\x86': '†',  # Dagger
            '\x87': '‡',  # Double dagger
            '\x88': 'ˆ',  # Modifier letter circumflex accent
            '\x89': '‰',  # Per mille sign
            '\x8a': 'Š',  # Latin capital letter s with caron
            '\x8b': '‹',  # Single left-pointing angle quotation mark
            '\x8c': 'Œ',  # Latin capital ligature oe
            '\x8d': '',   # Unused
            '\x8e': 'Ž',  # Latin capital letter z with caron
            '\x8f': '',   # Unused
            '\x90': '',   # Unused
            '\x91': "'",  # Left single quotation mark
            '\x92': "'",  # Right single quotation mark
            '\x93': '"',  # Left double quotation mark
            '\x94': '"',  # Right double quotation mark
            '\x95': '•',  # Bullet
            '\x96': '–',  # En dash
            '\x97': '—',  # Em dash
            '\x98': '~',  # Small tilde
            '\x99': '™',  # Trade mark sign
            '\x9a': 'š',  # Latin small letter s with caron
            '\x9b': '›',  # Single right-pointing angle quotation mark
            '\x9c': 'œ',  # Latin small ligature oe
            '\x9d': '',   # Unused
            '\x9e': 'ž',  # Latin small letter z with caron
            '\x9f': 'Ÿ',  # Latin capital letter y with diaeresis
            '\xa0': ' ',  # Non-breaking space
        }
        
        for old_char, new_char in replacements.items():
            content = content.replace(old_char, new_char)
        
        # Remove any remaining control characters that could cause issues
        content = ''.join(char for char in content if ord(char) >= 32 or char in '\n\r\t')
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"✅ Downloaded and cleaned {len(content)} characters to {output_path}")
        return True
        
    except Exception as e:
        print(f"❌ Failed to download company identifiers: {e}")
        return False


def create_yaml_database(company_records: List[Dict[str, any]], output_path: str) -> None:
    """Create YAML database file compatible with baconfreak."""
    
    # Sort by company ID for consistent output
    company_records.sort(key=lambda x: x['value'])
    
    yaml_data = {
        'company_identifiers': company_records
    }
    
    print(f"📝 Writing {len(company_records)} company records to {output_path}")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        # Add header comment
        f.write(f"""# Bluetooth SIG Company Identifiers Database
# Generated from: https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/company_identifiers/company_identifiers.yaml
# Total entries: {len(company_records)}
# 
# This file contains Bluetooth company identifiers (16-bit values) and their assigned company names.
# Used by baconfreak BLE plugin for device manufacturer identification.
# 
# Company IDs are assigned by the Bluetooth SIG to manufacturers who register
# for a company identifier to be used in the manufacturer specific data field
# of advertising packets and other Bluetooth protocols.

""")
        yaml.dump(yaml_data, f, default_flow_style=False, allow_unicode=True, width=100)
    
    print(f"✅ Created YAML database with {len(company_records)} entries")


def print_statistics(company_records: List[Dict[str, any]]) -> None:
    """Print statistics about the company identifiers database."""
    print(f"\n📊 Company Identifiers Database Statistics:")
    print(f"   Total company entries: {len(company_records)}")
    
    # ID range analysis
    min_id = min(record['value'] for record in company_records)
    max_id = max(record['value'] for record in company_records)
    print(f"   Company ID range: {min_id} (0x{min_id:04X}) to {max_id} (0x{max_id:04X})")
    
    # Company name analysis
    name_lengths = [len(record['name']) for record in company_records]
    avg_length = sum(name_lengths) / len(name_lengths)
    print(f"   Average company name length: {avg_length:.1f} characters")
    
    # Sample of well-known companies
    well_known = ['Apple', 'Google', 'Microsoft', 'Samsung', 'Intel', 'Qualcomm', 'Nordic', 'Texas Instruments']
    print(f"   Well-known companies found:")
    found_count = 0
    for record in company_records:
        name = record['name']
        for known in well_known:
            if known.lower() in name.lower():
                print(f"     ID {record['value']:5d} (0x{record['value']:04X}) - {name}")
                found_count += 1
                break
    
    if found_count == 0:
        print("     [Sample companies not found in expected format]")
    
    # Latest additions (highest IDs)
    print(f"   Latest registered companies (top 5):")
    latest = sorted(company_records, key=lambda x: x['value'], reverse=True)[:5]
    for record in latest:
        print(f"     ID {record['value']:5d} (0x{record['value']:04X}) - {record['name']}")


def main():
    """Main script entry point."""
    parser = argparse.ArgumentParser(description='Update Bluetooth company identifiers from Bluetooth SIG')
    parser.add_argument('--url', 
                       default='https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/company_identifiers/company_identifiers.yaml',
                       help='URL to download company identifiers from')
    parser.add_argument('--output', default='external/bluetooth_sig_identifiers.yaml',
                       help='Output YAML file path')
    parser.add_argument('--temp-yaml', default='/tmp/bluetooth_sig_companies.yaml',
                       help='Temporary file for downloaded company_identifiers.yaml')
    parser.add_argument('--download', action='store_true',
                       help='Download fresh data (otherwise use existing temp file)')
    
    args = parser.parse_args()
    
    # Ensure output directory exists
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Download if requested or file doesn't exist
    temp_yaml_path = Path(args.temp_yaml)
    if args.download or not temp_yaml_path.exists():
        if not download_company_identifiers(args.url, args.temp_yaml):
            return 1
    
    # Parse the company identifiers database
    parser = BluetoothSIGParser()
    company_records = parser.parse_company_file(args.temp_yaml)
    
    if not company_records:
        print("❌ No company records found!")
        return 1
    
    # Create YAML database
    create_yaml_database(company_records, args.output)
    
    # Print statistics
    print_statistics(company_records)
    
    print(f"\n🎉 Successfully created Bluetooth company identifiers database: {args.output}")
    print(f"💡 You can now update baconfreak BLE configuration to use this file")
    
    return 0


if __name__ == '__main__':
    exit(main())