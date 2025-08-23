"""
Configuration management using Dynaconf.
"""

from pathlib import Path
from typing import List, Optional

from dynaconf import Dynaconf
from pydantic import BaseModel, Field, validator

from .models import ScanConfiguration


class BaconFreakConfig:
    """Configuration management for baconfreak using Dynaconf."""

    def __init__(self, settings_files: Optional[List[str]] = None):
        """
        Initialize configuration with Dynaconf.

        Args:
            settings_files: List of configuration files to load
        """
        # Base directory is the project root (one level up from src/)
        self.base_dir = Path(__file__).parent.parent

        # Default settings files
        if settings_files is None:
            settings_files = [
                str(self.base_dir / "settings.toml"),
                str(self.base_dir / "settings.local.toml"),
                ".secrets.toml",
            ]

        # Initialize Dynaconf without environments support
        self.settings = Dynaconf(
            environments=False,
            settings_files=settings_files,
            env_prefix="BFREAK",
            load_dotenv=True,
            dotenv_path=str(self.base_dir / ".env"),
            merge_enabled=True,
            envvar_prefix="BFREAK",
            lowercase_read=False,
        )

        # Ensure directories exist
        self.ensure_directories()

    @property
    def base_dir_path(self) -> Path:
        """Get base directory as Path object."""
        return Path(self.settings.get("paths.base_dir", self.base_dir))

    @property
    def output_dir_path(self) -> Path:
        """Get output directory as Path object."""
        return Path(self.settings.get("paths.output_dir", self.base_dir / "output"))

    @property
    def assets_dir_path(self) -> Path:
        """Get assets directory as Path object."""
        return Path(self.settings.get("paths.assets_dir", self.base_dir / "assets"))

    @property
    def external_dir_path(self) -> Path:
        """Get external directory as Path object."""
        return Path(self.settings.get("paths.external_dir", self.base_dir / "external"))

    @property
    def logs_dir_path(self) -> Path:
        """Get logs directory as Path object."""
        return Path(self.settings.get("paths.logs_dir", self.base_dir / "logs"))

    @property
    def known_pcap_path(self) -> Path:
        """Get path for known devices PCAP file."""
        filename = self.settings.get("output.known_pcap", "bfreak-known.pcap")
        return self.output_dir_path / filename

    @property
    def unknown_pcap_path(self) -> Path:
        """Get path for unknown devices PCAP file."""
        filename = self.settings.get("output.unknown_pcap", "bfreak-unknown.pcap")
        return self.output_dir_path / filename

    @property
    def devices_pcap_path(self) -> Path:
        """Get path for specific device types PCAP file."""
        filename = self.settings.get("output.devices_pcap", "bfreak-devices.pcap")
        return self.output_dir_path / filename

    @property
    def device_types_for_devices_pcap(self) -> List[str]:
        """Get list of device types to save to devices PCAP file."""
        return self.settings.get(
            "output.device_types_for_devices_pcap",
            ["tile", "airtag_unregistered", "airtag_registered"],
        )

    @property
    def unified_identifiers_db_path(self) -> Path:
        """Get path for unified identifiers database."""
        filename = self.settings.get("database.unified_identifiers_db", "identifiers.db")
        return self.assets_dir_path / filename

    @property
    def company_identifiers_db_path(self) -> Path:
        """Get path for company identifiers database (legacy compatibility)."""
        return self.unified_identifiers_db_path

    @property
    def company_identifiers_sources(self) -> List[Path]:
        """Get list of company identifier source files."""
        external_dir = self.external_dir_path
        sources = self.settings.get(
            "database.sources", ["bluetooth_sig_identifiers.yaml", "custom_identifiers.yaml"]
        )
        return [external_dir / source for source in sources]

    @property
    def oui_identifiers_db_path(self) -> Path:
        """Get path for OUI identifiers database (legacy compatibility)."""
        return self.unified_identifiers_db_path

    @property
    def oui_identifiers_sources(self) -> List[Path]:
        """Get list of OUI identifier source files."""
        external_dir = self.external_dir_path
        sources = self.settings.get(
            "database.oui_sources", ["ieee_oui_identifiers.yaml", "custom_oui_identifiers.yaml"]
        )
        return [external_dir / source for source in sources]

    @property
    def scan_config(self) -> ScanConfiguration:
        """Get scan configuration as Pydantic model."""
        # Handle backward compatibility for integer interfaces
        interface_raw = self.settings.get("bluetooth.interface", "hci1")
        if isinstance(interface_raw, int):
            interface = f"hci{interface_raw}"
        else:
            interface = interface_raw

        return ScanConfiguration(
            interface=interface,
            scan_timeout=self.settings.get("bluetooth.scan_timeout", 0),
            filter_duplicates=self.settings.get("bluetooth.filter_duplicates", False),
            output_dir=str(self.output_dir_path),
            known_pcap_filename=self.settings.get("output.known_pcap", "bfreak-known.pcap"),
            unknown_pcap_filename=self.settings.get("output.unknown_pcap", "bfreak-unknown.pcap"),
            devices_pcap_filename=self.settings.get("output.devices_pcap", "bfreak-devices.pcap"),
            device_timeout=self.settings.get("detection.device_timeout", 300),
            min_rssi=self.settings.get("detection.min_rssi", -100),
            max_devices=self.settings.get("detection.max_devices", 10000),
            log_level=self.settings.get("logging.level", "INFO"),
            log_file=self.settings.get("logging.file"),
        )

    # Legacy property compatibility
    @property
    def bluetooth_interface(self) -> str:
        """Get Bluetooth interface name."""
        # Handle backward compatibility for integer interfaces
        interface_raw = self.settings.get("bluetooth.interface", "hci1")
        if isinstance(interface_raw, int):
            return f"hci{interface_raw}"
        else:
            return interface_raw

    @property
    def scan_timeout(self) -> int:
        """Get scan timeout in seconds (0 = infinite)."""
        return self.settings.get("bluetooth.scan_timeout", 0)

    @property
    def filter_duplicates(self) -> bool:
        """Get whether to filter duplicate packets."""
        return self.settings.get("bluetooth.filter_duplicates", False)

    @property
    def log_level(self) -> str:
        """Get logging level."""
        return self.settings.get("logging.level", "INFO")

    @property
    def db_batch_size(self) -> int:
        """Get database batch size for bulk operations."""
        return self.settings.get("database.batch_size", 500)

    def ensure_directories(self):
        """Create necessary directories if they don't exist with proper user permissions."""
        import os
        
        directories = [self.output_dir_path, self.assets_dir_path, self.logs_dir_path]

        # Get the original user info if running under sudo
        original_uid = None
        original_gid = None
        
        if os.getuid() == 0:  # Running as root (likely via sudo)
            # Try to get original user from SUDO_UID environment variable
            sudo_uid = os.environ.get('SUDO_UID')
            sudo_gid = os.environ.get('SUDO_GID')
            
            if sudo_uid and sudo_gid:
                original_uid = int(sudo_uid)
                original_gid = int(sudo_gid)

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            
            # If running as root but we have original user info, fix ownership
            if original_uid is not None and original_gid is not None:
                try:
                    os.chown(str(directory), original_uid, original_gid)
                except (OSError, PermissionError) as e:
                    # Log warning but don't fail - directory creation is more important
                    import logging
                    logging.getLogger(__name__).warning(
                        f"Could not change ownership of {directory} to user {original_uid}:{original_gid}: {e}"
                    )

    def get(self, key: str, default=None):
        """Get configuration value by key."""
        return self.settings.get(key, default)

    def set(self, key: str, value):
        """Set configuration value."""
        self.settings.set(key, value)

    def reload(self):
        """Reload configuration from files."""
        self.settings.reload()

    def dump(self) -> dict:
        """Dump all configuration as dictionary."""
        return dict(self.settings)

    def get_plugin_config(self, protocol: str) -> dict:
        """Get plugin-specific configuration."""
        return self.settings.get(f"plugins.{protocol}", {})


# Global configuration instance
config = BaconFreakConfig()
