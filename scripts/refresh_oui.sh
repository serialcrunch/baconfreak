#!/bin/bash
#
# Quick script to refresh the IEEE OUI database for baconfreak
# This downloads fresh data from IEEE and regenerates the YAML database
#

set -e

echo "🔄 Refreshing IEEE OUI Database for baconfreak"
echo "=============================================="

cd "$(dirname "$0")/.."

# Check if we're in the right directory
if [ ! -f "settings.toml" ]; then
    echo "❌ Error: Run this script from the baconfreak root directory"
    exit 1
fi

# Create scripts directory if it doesn't exist
mkdir -p scripts

# Run the update script
echo "📥 Downloading latest IEEE OUI database..."
python scripts/update_oui_database.py --download

echo ""
echo "✅ IEEE OUI Database Successfully Updated!"
echo ""
echo "📊 Next steps:"
echo "  • The database is automatically loaded by baconfreak"
echo "  • Custom overrides in external/custom_oui_identifiers.yaml are preserved"
echo "  • Run 'sudo python main.py scan --plugins wifi' to use the new database"
echo ""
echo "🎯 For fresh database in running instance:"
echo "  • Stop baconfreak and delete assets/oui_identifiers.db"
echo "  • Restart baconfreak to regenerate with new data"