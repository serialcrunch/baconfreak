#!/bin/bash
#
# Comprehensive script to refresh both IEEE OUI and Bluetooth SIG databases for baconfreak
# This downloads fresh data from official sources and regenerates all YAML databases
#

set -e

echo "🔄 Refreshing All Official Databases for baconfreak"
echo "=================================================="

cd "$(dirname "$0")/.."

# Check if we're in the right directory
if [ ! -f "settings.toml" ]; then
    echo "❌ Error: Run this script from the baconfreak root directory"
    exit 1
fi

echo ""
echo "📡 Step 1: Updating IEEE OUI Database (WiFi Vendors)"
echo "----------------------------------------------------"
python scripts/update_oui_database.py --download

echo ""
echo "🔵 Step 2: Updating Bluetooth SIG Company Identifiers (BLE Manufacturers)"  
echo "------------------------------------------------------------------------"
python scripts/update_bluetooth_companies.py --download

echo ""
echo "✅ All Official Databases Successfully Updated!"
echo ""
echo "📊 Database Summary:"
echo "  • IEEE OUI Database: 37,822+ WiFi vendor identifiers"
echo "  • Bluetooth SIG Database: 3,927+ BLE company identifiers"
echo "  • Custom overrides preserved in both WiFi and BLE plugins"
echo ""
echo "🎯 Next steps:"
echo "  • Databases are automatically loaded by baconfreak"
echo "  • Run 'sudo python main.py scan' to use the updated data"
echo "  • For immediate database refresh, delete assets/*.db files and restart"
echo ""
echo "🌟 Your baconfreak installation now has the most comprehensive"
echo "   vendor identification coverage available!"