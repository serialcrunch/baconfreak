"""
Logging configuration using Loguru.
"""

import sys
from pathlib import Path
from typing import Any, Dict, Optional

from loguru import logger
from rich.console import Console
from rich.logging import RichHandler

from .config import config


class LoguruConfig:
    """Logging configuration using Loguru and Rich."""

    def __init__(self):
        self.console = Console(
            width=config.get("rich.console_width", 120),
            force_terminal=config.get("rich.console_force_terminal", False),
            no_color=config.get("rich.console_no_color", False),
        )
        self.configured = False

    def setup(
        self,
        level: Optional[str] = None,
        log_file: Optional[str] = None,
        enable_rich: bool = True,
        tui_mode: bool = False,
    ) -> None:
        """
        Configure Loguru logging with Rich integration.

        Args:
            level: Log level (TRACE, DEBUG, INFO, SUCCESS, WARNING, ERROR, CRITICAL)
            log_file: Optional log file path
            enable_rich: Enable Rich formatting for console output
            tui_mode: When True, disable console output to prevent TUI interference
        """
        if self.configured:
            return

        # Remove default handler
        logger.remove()

        # Get configuration
        log_level = level or config.get("logging.level", "INFO")
        log_format = config.get(
            "logging.format",
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>",
        )

        # Console handler (disabled in TUI mode to prevent interference)
        if not tui_mode:
            if enable_rich:
                # Rich handler for beautiful console output
                rich_handler = RichHandler(
                    console=self.console,
                    show_path=False,
                    show_time=False,
                    rich_tracebacks=True,
                    tracebacks_show_locals=False,
                )

                logger.add(
                    rich_handler, level=log_level, format="{message}", backtrace=True, diagnose=True
                )
            else:
                # Standard console handler
                logger.add(
                    sys.stderr,
                    level=log_level,
                    format=log_format,
                    colorize=True,
                    backtrace=True,
                    diagnose=True,
                )

        # File handler (always enabled, especially important in TUI mode)
        file_path = None
        if log_file:
            file_path = Path(log_file)
            if not file_path.is_absolute():
                file_path = config.logs_dir_path / file_path
        elif config.get("logging.file"):
            configured_file = Path(config.get("logging.file"))
            if not configured_file.is_absolute():
                file_path = config.logs_dir_path / configured_file
            else:
                file_path = configured_file
        else:
            # Default log file when in TUI mode or when no file specified
            file_path = config.logs_dir_path / "baconfreak.log"

        if file_path:
            # Ensure log directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)

            logger.add(
                str(file_path),
                level=log_level,
                format=log_format,
                rotation=config.get("logging.rotation", "10 MB"),
                retention=config.get("logging.retention", "7 days"),
                compression="gz",
                backtrace=True,
                diagnose=True,
            )

        # Suppress noisy third-party loggers
        self._configure_third_party_loggers()

        self.configured = True
        if not tui_mode:
            logger.info(f"Logging configured with level: {log_level}")

    def _configure_third_party_loggers(self):
        """Configure third-party loggers to reduce noise."""
        import logging

        # Suppress scapy logging
        logging.getLogger("scapy").setLevel(logging.WARNING)
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

        # Suppress other noisy loggers
        noisy_loggers = [
            "urllib3.connectionpool",
            "requests.packages.urllib3",
            "asyncio",
            "concurrent.futures",
        ]

        for logger_name in noisy_loggers:
            logging.getLogger(logger_name).setLevel(logging.WARNING)


class BaconFreakLogger:
    """Specialized logger for baconfreak operations using Loguru."""

    def __init__(self, name: str = "baconfreak"):
        self.name = name
        self.logger = logger.bind(name=name)

        # Ensure logging is configured
        if not loguru_config.configured:
            loguru_config.setup()

    def device_detected(
        self,
        device_type: str,
        addr: str,
        rssi: int,
        data: Optional[str] = None,
        company_name: Optional[str] = None,
    ):
        """Log device detection with structured data."""
        extra_data = {
            "device_type": device_type,
            "addr": addr,
            "rssi": rssi,
            "company_name": company_name,
        }

        if data:
            # Truncate long data for readability
            display_data = data[:50] + "..." if len(data) > 50 else data
            extra_data["data"] = display_data

        msg = f"Device detected: {device_type} @ {addr} (RSSI: {rssi})"
        if company_name:
            msg += f" [{company_name}]"
        if data:
            msg += f" Data: {display_data}"

        self.logger.bind(**extra_data).info(msg)

    def company_lookup(self, company_id: int, company_name: Optional[str] = None):
        """Log company ID lookup."""
        if company_name:
            self.logger.bind(company_id=company_id, company_name=company_name).debug(
                f"Company resolved: {company_id} -> {company_name}"
            )
        else:
            self.logger.bind(company_id=company_id).debug(f"Unknown company ID: {company_id}")

    def packet_milestone(self, total_packets: int, rate: Optional[float] = None):
        """Log packet processing milestone."""
        msg = f"Processed {total_packets:,} packets"
        if rate:
            msg += f" ({rate:.1f} pkt/s)"

        self.logger.bind(total_packets=total_packets, packet_rate=rate).info(msg)

    def session_stats(
        self,
        devices: int,
        packets: int,
        duration: float,
        known_companies: int = 0,
        unknown_companies: int = 0,
    ):
        """Log session statistics."""
        rate = packets / duration if duration > 0 else 0

        self.logger.bind(
            devices=devices,
            packets=packets,
            duration=duration,
            packet_rate=rate,
            known_companies=known_companies,
            unknown_companies=unknown_companies,
        ).success(
            f"Session complete: {devices} devices, {packets:,} packets, "
            f"{duration:.1f}s ({rate:.1f} pkt/s)"
        )

    def interface_status(self, interface: int, status: str, details: str = ""):
        """Log Bluetooth interface status."""
        msg = f"HCI{interface}: {status}"
        if details:
            msg += f" - {details}"

        self.logger.bind(interface=interface, status=status).info(msg)

    def error_with_context(self, error: Exception, context: str, **extra_context):
        """Log error with context information."""
        self.logger.bind(error_type=type(error).__name__, context=context, **extra_context).error(
            f"{context}: {str(error)}"
        )

    def performance_metric(self, metric_name: str, value: float, unit: str = "", **extra_data):
        """Log performance metrics."""
        msg = f"{metric_name}: {value}"
        if unit:
            msg += f" {unit}"

        self.logger.bind(metric=metric_name, value=value, unit=unit, **extra_data).debug(msg)

    def security_event(self, event_type: str, severity: str, description: str, **context):
        """Log security-related events."""
        self.logger.bind(event_type=event_type, severity=severity, **context).warning(
            f"Security event [{event_type}]: {description}"
        )

    def startup_info(self, interface: int, output_dir: Path, config_summary: Dict[str, Any]):
        """Log startup information with configuration."""
        self.logger.bind(
            interface=interface, output_dir=str(output_dir), config=config_summary
        ).info(f"Starting baconfreak on HCI{interface}, output: {output_dir}")

    def shutdown_info(self, total_devices: int, total_packets: int, duration: float):
        """Log shutdown information."""
        rate = total_packets / duration if duration > 0 else 0

        self.logger.bind(
            devices=total_devices, packets=total_packets, duration=duration, rate=rate
        ).info(
            f"Shutdown complete: {total_devices} devices, "
            f"{total_packets:,} packets in {duration:.1f}s"
        )


# Global loguru configuration
loguru_config = LoguruConfig()


# Convenience function for setup
def setup_logging(
    level: Optional[str] = None,
    log_file: Optional[str] = None,
    enable_rich: bool = True,
    tui_mode: bool = False,
) -> BaconFreakLogger:
    """
    Setup modern logging with Loguru and Rich.

    Args:
        level: Log level
        log_file: Optional log file
        enable_rich: Enable Rich console output
        tui_mode: When True, disable console output to prevent TUI interference

    Returns:
        Configured BaconFreakLogger instance
    """
    loguru_config.setup(level, log_file, enable_rich, tui_mode)
    return BaconFreakLogger()


# Export logger instance
logger = logger
