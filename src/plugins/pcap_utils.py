"""
Common PCAP file management utilities.
"""

from contextlib import contextmanager
from pathlib import Path
from typing import Dict

from scapy.utils import PcapWriter


class PcapManager:
    """Manages PCAP writers with common patterns."""

    @staticmethod
    @contextmanager
    def pcap_writers_context(output_files: Dict[str, Path]):
        """Context manager for PCAP writers with standardized error handling."""
        writers = {}
        try:
            # Ensure output directory exists
            for file_path in output_files.values():
                file_path.parent.mkdir(parents=True, exist_ok=True)

            # Create writers for each output file
            for key, file_path in output_files.items():
                writers[key] = PcapWriter(str(file_path))

            yield writers

        finally:
            # Cleanup: close all writers
            for writer in writers.values():
                if writer:
                    try:
                        writer.close()
                    except Exception:
                        # Ignore errors during cleanup
                        pass

    @staticmethod
    def ensure_output_directory(output_files: Dict[str, Path]) -> None:
        """Ensure all output directories exist."""
        for file_path in output_files.values():
            file_path.parent.mkdir(parents=True, exist_ok=True)
