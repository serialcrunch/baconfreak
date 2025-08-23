# 🥓 baconfreak: BLE & WiFi Packet Analysis Tool

A modern, Python-based tool for capturing and analyzing BLE advertising packets and WiFi frames. Built with industry-standard packages like **Pydantic**, **Loguru**, **Rich**, and **Typer** for professional-grade wireless security research and monitoring.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## ✨ Features

### 🎯 **Core Capabilities**
- **📡 Real-time BLE packet capture** using Scapy and HCI sockets
- **📶 WiFi monitoring** with multi-band support (2.4GHz, 5GHz, 6E) and intelligent channel hopping
- **🏷️ Smart device detection** for Apple devices (AirTags, AirPods), Tile trackers, and more
- **🏢 Company identifier resolution** using Bluetooth SIG database
- **📊 PCAP output** for analysis with Wireshark and other tools
- **📈 Live statistics** with device categorization and performance metrics

### 🎨 **Modern Interface**
- **🌈 Beautiful CLI** with Rich-powered colored output and tables
- **📊 Live monitoring** with real-time device detection display  
- **🩺 System diagnostics** with health checks and validation
- **⚙️ Interactive configuration** management and display

### 🛡️ **Professional Features**
- **🔧 Type-safe models** with Pydantic v2 validation
- **📝 Structured logging** with Loguru for better debugging
- **⚙️ Flexible configuration** using Dynaconf
- **🧪 Comprehensive testing** with pytest and coverage
- **🏗️ Modular architecture** for easy extension and maintenance

## Requirements

### Core Requirements
- Python 3.8+
- Root privileges (for Bluetooth HCI and WiFi monitor mode access)
- Linux system with BlueZ stack

### Device Support
- **Bluetooth**: Bluetooth adapter with BLE support
- **WiFi**: WiFi adapter with monitor mode support (for WiFi plugin)

### System Dependencies
- **Bluetooth tools**: hciconfig, hcitool (usually pre-installed)
- **WiFi tools**: iw, iwconfig (install with `sudo apt install iw wireless-tools`)

## Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd baconfreak
   ```

2. **Quick setup using the shell script:**
   ```bash
   ./baconfreak.sh --setup
   ```

   **Or manual setup:**
   ```bash
   # Create and activate virtual environment
   python3 -m venv .venv
   source .venv/bin/activate
   
   # Install dependencies
   pip install -e ".[dev]"
   ```

4. **Install system dependencies and set up interfaces:**
   ```bash
   # Install WiFi tools (for WiFi plugin)
   sudo apt install iw wireless-tools
   
   # Set up Bluetooth interface
   sudo hciconfig hci1 up
   
   # Check WiFi interface (for WiFi plugin)
   ip link show  # Find your WiFi interface (wlan0, wlp*, etc.)
   ```

## 🚀 Usage

### 🎯 **CLI Interface (Recommended)**

```bash
# 🩺 Run system diagnostics
python main.py doctor

# ⚙️ Show current configuration  
python main.py config-show

# 🛰️ Start scanning with beautiful interface
sudo python main.py scan --interface 1 --log-level INFO

# 📊 Advanced scanning with custom settings
sudo python main.py scan --min-rssi -80 --timeout 300 --output ./captures

# 📶 WiFi monitoring (with plugin enabled in settings)
sudo python main.py scan --plugins wifi --interface wlan0
```

### 🚀 **Shell Script Wrapper (Easiest)**

```bash
# Check system requirements
./baconfreak.sh --check

# Start scanning (handles sudo automatically)
./baconfreak.sh scan

# Run diagnostics
./baconfreak.sh doctor

# Update official databases (IEEE OUI + Bluetooth SIG)
./baconfreak.sh refresh-databases

# Advanced scanning
./baconfreak.sh scan --interface 1 --log-level DEBUG
```

### 🎨 **Rich Output Examples**

The CLI provides beautiful, colorized output:

```
🩺 baconfreak System Diagnostics
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Check               ┃ Status  ┃ Details               ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━┩
│ Python Version      │ ✅ PASS │ Python 3.10.12        │
│ Bluetooth Interface │ ✅ PASS │ HCI1 available         │
│ Permissions         │ ❌ FAIL │ Root privileges needed │
└─────────────────────┴─────────┴───────────────────────┘
```

### ⚙️ **Configuration**

Configuration using TOML format:

```bash
# Use default settings.toml
python main.py scan

# Create custom configuration
cp settings.toml my_settings.toml
python main.py scan --config my_settings.toml

# Use environment variables for overrides (note double underscores for nested values)
BFREAK_LOGGING__LEVEL=DEBUG python main.py scan
BFREAK_DETECTION__MIN_RSSI=-80 python main.py scan
```

#### Configuration Options

```toml
[plugins.ble]
enabled = true        # Enable/disable BLE plugin
interface = "hci1"    # HCI interface name
scan_timeout = 0      # Scan duration (0 = infinite)
filter_duplicates = false
min_rssi = -100       # Minimum signal strength

[plugins.wifi]
enabled = false       # Enable/disable WiFi plugin  
interface = "wlan0"   # WiFi interface name
monitor_mode = true   # Enable monitor mode
scan_timeout = 0      # Scan duration (0 = infinite)
channel_hop = true    # Enable automatic channel hopping
min_rssi = -100       # Minimum signal strength
channel_hop_interval = 2.0  # Seconds between channel changes

# Multi-band support
enable_2_4ghz = true  # Enable 2.4GHz band scanning
enable_5ghz = false   # Enable 5GHz band scanning (requires adapter support)
enable_6e = false     # Enable 6E band scanning (requires WiFi 6E adapter)

# Manual channel override (disables band-based selection)
channels = [1, 6, 11] # Specific channels to scan

[detection]  
device_timeout = 300  # Device staleness threshold
max_devices = 10000   # Maximum devices to track

[logging]
level = "INFO"        # Log verbosity
rotation = "10 MB"    # Log file rotation
retention = "7 days"  # Log retention period
```

## Architecture

The codebase follows clean architecture principles:

### **Entry Points**
- **`main.py`** - CLI interface using Typer and Rich
- **`baconfreak.sh`** - Shell wrapper with auto-sudo and environment setup

### **Business Logic (`src/`)**
- **`src/baconfreak.py`** - Core Bluetooth scanner with Rich UI
- **`src/config.py`** - Environment-aware configuration with Dynaconf
- **`src/models.py`** - Type-safe Pydantic models for validation
- **`src/device_detector.py`** - Smart device classification logic
- **`src/company_identifiers.py`** - Bluetooth SIG database management
- **`src/logger.py`** - Structured logging with Loguru and Rich integration

### **Configuration & Data**
- **`settings.toml`** - Main configuration with environment overrides
- **`external/`** - Company identifier YAML sources
- **`tests/`** - Comprehensive test suite with pytest

## Device Detection

The tool can identify:

- **Tile Trackers** - Based on service UUID 65261
- **Apple AirTags** - Both registered and unregistered variants
- **Apple AirPods** - Various models
- **Other Apple Devices** - Generic Apple device detection
- **Unknown Devices** - Any BLE device with manufacturer data

## BLE Company Identification

The BLE plugin includes **Bluetooth SIG Company Identifier** lookup for manufacturer identification:

### **Comprehensive Company Database**
- **3,927+ Official Company IDs** from the Bluetooth SIG database
- **Complete manufacturer coverage** including Apple (ID 76), Google (ID 224/398), Microsoft (ID 6), Samsung (ID 117), Intel (ID 2), Qualcomm (multiple IDs), and thousands more
- **Automatic lookup** for all detected BLE devices with manufacturer data
- **Real-time company display** in the live monitoring interface
- **Historical coverage** from early Bluetooth companies to latest registrations

### **Custom Company Identifiers**

You can add custom company ID mappings by editing **`external/custom_identifiers.yaml`**:

```yaml
company_identifiers:
  # Custom company assignments
  - company_id: 65535
    company_name: "My Test Company"
    
  # Override standard companies with specific info
  - company_id: 76
    company_name: "Apple Inc. (Cupertino)"
    
  # Private/experimental company IDs
  - company_id: 65534
    company_name: "Internal R&D Division"
```

**Key Features:**
- ✅ **Override Support**: Custom entries override standard Bluetooth SIG database
- ✅ **Private ID Support**: Perfect for internal development and testing
- ✅ **Easy Updates**: Run `python scripts/update_bluetooth_companies.py --download` for latest official data
- ✅ **Comprehensive Coverage**: From ID 0 (Ericsson) to latest registrations

## WiFi Vendor Identification

The WiFi plugin includes **OUI (Organizationally Unique Identifier)** lookup for MAC address vendor identification:

### **Comprehensive Vendor Database**
- **37,822+ Official OUIs** from the IEEE Standards Association database
- **Complete vendor coverage** including Apple (1,413 OUIs), Huawei (1,876 OUIs), Cisco (1,191 OUIs), Samsung (847 OUIs), Intel (629 OUIs), and thousands more
- **Automatic lookup** for all detected WiFi devices (access points, clients)
- **Real-time vendor display** in the live monitoring interface
- **Randomized MAC detection** for privacy-enabled devices (iOS, Android, Windows 10)

### **Custom OUI Identifiers**

You can add custom OUI-to-vendor mappings by editing **`external/custom_oui_identifiers.yaml`**:

```yaml
oui_identifiers:
  # Custom organizational devices
  - oui: "AA:BB:CC"
    vendor_name: "My Company Device"
    
  # Override standard vendors with specific info
  - oui: "00:05:02"
    vendor_name: "Apple MacBook Pro"
    
  # Private/locally administered addresses
  - oui: "02:42:00"
    vendor_name: "Docker Container"
  - oui: "52:54:00"
    vendor_name: "QEMU/KVM Virtual NIC"
```

**Key Features:**
- ✅ **Override Support**: Custom entries override standard IEEE database
- ✅ **Private OUI Support**: Perfect for locally administered addresses
- ✅ **Docker/VM Recognition**: Built-in recognition for virtualization platforms
- ✅ **Easy Updates**: Run `python main.py update-oui-db` to reload custom entries
- ✅ **Fresh IEEE Data**: Update with `python scripts/update_oui_database.py --download` for latest official OUIs

**Common Use Cases:**
- **Organization Networks**: Label your company's devices
- **Lab Environments**: Identify test equipment and VMs
- **Home Networks**: Custom names for personal devices
- **Security Research**: Enhanced device categorization

## Output Files

### Bluetooth Files
- **`output/bfreak-known.pcap`** - Packets from known company IDs
- **`output/bfreak-unknown.pcap`** - Packets from unknown company IDs

### WiFi Files (when WiFi plugin enabled)
- **`output/wifi-beacons.pcap`** - WiFi beacon frames
- **`output/wifi-probes.pcap`** - WiFi probe request/response frames
- **`output/wifi-data.pcap`** - WiFi data frames
- **`output/wifi-all.pcap`** - All captured WiFi frames

### System Files
- **`logs/baconfreak.log`** - Application logs with rotation and retention
- **`assets/company_identifiers.db`** - SQLite database of Bluetooth SIG identifiers
- **`external/`** - YAML configuration files for company data sources

## Testing

Run the comprehensive test suite:

```bash
# Run all tests with coverage
python -m pytest tests/ --cov=src

# Run specific test files
python -m pytest tests/unit/test_device_detector.py -v

# Run specific test modules
python -m pytest tests/unit/test_config.py -v
```

**Note**: Use environment variables like `BFREAK_LOGGING__LEVEL=DEBUG` to override configuration during testing.

## Quick Start

```bash
# 1. Clone and setup
git clone <repository-url>
cd baconfreak
./baconfreak.sh --setup

# 2. Check system requirements
./baconfreak.sh --check

# 3. Start scanning
./baconfreak.sh scan
```

## Development

### Code Quality

The refactored code addresses several issues from the original:

- ✅ **Fixed hard-coded paths** - Now uses configurable paths
- ✅ **Improved error handling** - Specific exceptions with proper logging
- ✅ **Security enhancements** - Safe YAML loading, specific imports
- ✅ **Resource management** - Context managers for file operations
- ✅ **Code organization** - Modular design with separation of concerns
- ✅ **Type safety** - Comprehensive type hints throughout
- ✅ **Documentation** - Proper docstrings and comments

### Contributing

1. Follow PEP 8 style guidelines
2. Add type hints to all functions
3. Write tests for new functionality
4. Update documentation as needed

## Security Considerations

- **Root privileges required** - Tool needs raw socket access for HCI operations
- **Safe YAML loading** - Uses `yaml.safe_load()` to prevent code injection
- **Input validation** - Validates packet data before processing
- **Logging security** - Sanitizes sensitive data in logs

## Troubleshooting

### Permission Errors
```bash
# Use the shell wrapper (handles sudo automatically)
./baconfreak.sh scan

# Or run CLI directly with sudo
sudo python main.py scan
```

### Bluetooth Interface Issues
```bash
# Check available interfaces
hciconfig

# Bring up interface
sudo hciconfig hci1 up

# Reset interface if needed
sudo hciconfig hci1 reset
```

### Database Issues
```bash
# Delete and recreate database
rm assets/company_identifiers.db

# Run tool to recreate database automatically
./baconfreak.sh doctor
```

### WiFi Interface Issues
```bash
# Check available WiFi interfaces
ip link show | grep wl

# Install WiFi tools
sudo apt install iw wireless-tools

# Check interface capabilities
iw dev wlan0 info

# Check if monitor mode is supported
sudo iw dev wlan0 set type monitor
sudo iw dev wlan0 set type managed  # restore

# Enable interface
sudo ip link set wlan0 up

# Check supported bands
iw phy info | grep -E "Band|MHz"
```

## License

This project is for educational and research purposes. Please ensure compliance with local laws and regulations regarding Bluetooth and WiFi monitoring and privacy.

## Acknowledgments

- Built using [Scapy](https://scapy.net/) for packet manipulation
- Company identifiers from [Bluetooth SIG](https://www.bluetooth.com/)
- Uses [Peewee ORM](http://docs.peewee-orm.com/) for database operations