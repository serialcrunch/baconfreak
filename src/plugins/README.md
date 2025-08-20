# Baconfreak Plugin System

This directory contains the pluggable framework for baconfreak, allowing support for different network capture protocols through individual plugin folders.

## Plugin Structure

Each plugin is contained in its own folder with the following structure:

```
src/plugins/
├── base.py                 # Base plugin classes and interfaces
├── registry.py             # Plugin registry with auto-discovery
├── discovery.py            # Plugin discovery system
├── manager.py              # Single plugin manager
├── tabbed_manager.py       # Multi-plugin tabbed manager
├── ble/                    # BLE plugin folder
│   ├── __init__.py
│   └── plugin.py          # BLE plugin implementation
├── wifi/                   # WiFi plugin folder
│   ├── __init__.py
│   └── plugin.py          # WiFi plugin implementation
└── your_plugin/            # Your custom plugin folder
    ├── __init__.py
    └── plugin.py          # Your plugin implementation
```

## Creating a New Plugin

To create a new plugin:

1. **Create a plugin folder**: Create a new directory under `src/plugins/` with your protocol name (e.g., `zigbee`, `lorawan`, etc.)

2. **Create the plugin files**:
   ```bash
   mkdir src/plugins/your_protocol
   touch src/plugins/your_protocol/__init__.py
   touch src/plugins/your_protocol/plugin.py
   ```

3. **Implement the plugin class** in `plugin.py`:
   ```python
   from ..base import CapturePlugin, PluginInfo
   
   class YourProtocolPlugin(CapturePlugin):
       @property
       def info(self) -> PluginInfo:
           return PluginInfo(
               name="Your Protocol Scanner",
               version="1.0.0",
               description="Description of your protocol",
               protocol="your_protocol",
               requires_root=True,  # or False
               supported_platforms=["linux"]
           )
       
       # Implement required abstract methods...
   ```

4. **Export the plugin** in `__init__.py`:
   ```python
   from .plugin import YourProtocolPlugin
   __all__ = ["YourProtocolPlugin"]
   ```

5. **Auto-discovery**: The plugin will be automatically discovered and registered when the application starts.

## Plugin Interface

All plugins must inherit from `CapturePlugin` and implement these abstract methods:

- `info` - Return plugin metadata
- `validate_config()` - Validate plugin configuration
- `check_requirements()` - Check system requirements
- `get_default_output_files()` - Define output file paths
- `initialize_capture()` - Initialize capture resources
- `start_capture()` - Start packet capture
- `stop_capture()` - Stop capture and cleanup
- `process_packet()` - Process captured packets
- `create_live_display()` - Create Rich UI layout
- `update_display()` - Update UI with current data
- `get_statistics()` - Return plugin statistics

## Plugin Configuration

Plugins can have protocol-specific configuration in `settings.toml`:

```toml
[plugins.your_protocol]
interface = "eth0"
timeout = 300
custom_setting = "value"
```

Access configuration in your plugin:
```python
def __init__(self, config: Dict[str, Any], console: Optional[Console] = None):
    super().__init__(config, console)
    self.interface = config.get("interface", "eth0")
    self.timeout = config.get("timeout", 300)
```

## Plugin Features

### Auto-Discovery
Plugins are automatically discovered from their folders. No manual registration required.

### Validation
Each plugin validates its configuration and system requirements before being allowed to run.

### Isolation
Each plugin runs in its own context with separate:
- Output files (with plugin-specific prefixes)
- Statistics tracking
- UI layouts and controls
- Error handling

### Tabbed Interface
Multiple plugins can run simultaneously with a tabbed interface:
- Automatic tab creation for each active plugin
- Tab switching with keyboard shortcuts
- Plugin-specific controls and displays

## Built-in Plugins

### BLE Plugin (`src/plugins/ble/`)
- **Protocol**: Bluetooth Low Energy
- **Interface**: HCI (e.g., hci1)
- **Features**: Device detection, manufacturer identification, RSSI tracking
- **Output Files**: `BLE-{timestamp}-ble-known.pcap`, `BLE-{timestamp}-ble-unknown.pcap`, etc.

### WiFi Plugin (`src/plugins/wifi/`)
- **Protocol**: WiFi (802.11)
- **Interface**: Monitor mode WiFi interface (e.g., wlan1)
- **Features**: Access point detection, client tracking, channel hopping
- **Output Files**: `WIFI-{timestamp}-wifi-beacons.pcap`, `WIFI-{timestamp}-wifi-probes.pcap`, etc.

## Usage Examples

```bash
# List available plugins
python main.py plugins

# Single protocol
sudo python main.py scan --protocol ble
sudo python main.py scan --protocol wifi

# Multiple protocols with tabbed interface
sudo python main.py scan --protocol ble --protocol wifi

# Protocol-specific options
sudo python main.py scan --protocol wifi --wifi-interface wlan0 --wifi-channels 1,6,11
```

## Development Notes

- Use relative imports within plugin packages
- Follow the established naming conventions
- Include comprehensive error handling
- Add unit tests for your plugin
- Document protocol-specific configuration options
- Consider platform compatibility in requirements checking