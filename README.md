# 🥓 baconfreak: Bluetooth Low Energy Analysis Tool

A modern, Python-based tool for capturing and analyzing Bluetooth Low Energy (BLE) advertising packets. Built with industry-standard packages like **Pydantic**, **Loguru**, **Rich**, and **Typer** for professional-grade Bluetooth security research and monitoring.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## ✨ Features

### 🎯 **Core Capabilities**
- **📡 Real-time BLE packet capture** using Scapy and HCI sockets
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
- **⚙️ Environment-aware configuration** using Dynaconf
- **🧪 Comprehensive testing** with pytest and coverage
- **🏗️ Modular architecture** for easy extension and maintenance

## Requirements

- Python 3.8+
- Root privileges (for Bluetooth HCI access)
- Bluetooth adapter with BLE support
- Linux system with BlueZ stack

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

4. **Set up Bluetooth interface:**
   ```bash
   sudo hciconfig hci1 up
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
```

### 🚀 **Shell Script Wrapper (Easiest)**

```bash
# Check system requirements
./baconfreak.sh --check

# Start scanning (handles sudo automatically)
./baconfreak.sh scan

# Run diagnostics
./baconfreak.sh doctor

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

# Environment-specific configuration (auto-detects DEVELOPMENT by default)
BFREAK_ENV=production python main.py scan   # Use production settings
BFREAK_ENV=development python main.py scan  # Use development settings (default)
```

#### Configuration Options

```toml
[default.bluetooth]
interface = 1          # HCI interface number
scan_timeout = 0       # Scan duration (0 = infinite)
filter_duplicates = false

[default.detection]  
min_rssi = -100       # Minimum signal strength
device_timeout = 300  # Device staleness threshold
max_devices = 10000   # Maximum devices to track

[default.logging]
level = "INFO"        # Log verbosity
rotation = "10 MB"    # Log file rotation
retention = "7 days"  # Log retention period

# Environment-specific overrides
[development]
logging.level = "DEBUG"
detection.min_rssi = -120

[production] 
logging.level = "WARNING"
logging.file = "baconfreak.log"
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

## Output Files

- **`output/bfreak-known.pcap`** - Packets from known company IDs
- **`output/bfreak-unknown.pcap`** - Packets from unknown company IDs
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

# Run tests in production mode (to avoid dev environment settings)
BFREAK_ENV=production python -m pytest tests/unit/test_config.py -v
```

**Note**: Tests may behave differently in development vs production environments due to configuration overrides in `settings.toml`.

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

## License

This project is for educational and research purposes. Please ensure compliance with local laws and regulations regarding Bluetooth monitoring and privacy.

## Acknowledgments

- Built using [Scapy](https://scapy.net/) for packet manipulation
- Company identifiers from [Bluetooth SIG](https://www.bluetooth.com/)
- Uses [Peewee ORM](http://docs.peewee-orm.com/) for database operations