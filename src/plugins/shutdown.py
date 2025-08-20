"""
Improved shutdown handling for scapy-based plugins.
"""

import atexit
import os
import signal
import subprocess
import threading
import time
from typing import Set

from loguru import logger


class ShutdownManager:
    """Manages clean shutdown of scapy processes and resources."""
    
    def __init__(self):
        self._active_plugins: Set = set()
        self._cleanup_registered = False
        self._shutdown_lock = threading.Lock()
    
    def register_plugin(self, plugin):
        """Register a plugin for cleanup on shutdown."""
        with self._shutdown_lock:
            self._active_plugins.add(plugin)
            if not self._cleanup_registered:
                self._register_cleanup_handlers()
                self._cleanup_registered = True
    
    def unregister_plugin(self, plugin):
        """Unregister a plugin from cleanup."""
        with self._shutdown_lock:
            self._active_plugins.discard(plugin)
    
    def _register_cleanup_handlers(self):
        """Register cleanup handlers for various shutdown scenarios."""
        # Register atexit handler
        atexit.register(self._emergency_cleanup)
        
        # Register signal handlers
        for sig in [signal.SIGTERM, signal.SIGINT]:
            try:
                signal.signal(sig, self._signal_handler)
            except (ValueError, OSError):
                pass  # Signal not available on this platform
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, initiating cleanup...")
        self._emergency_cleanup()
    
    def _emergency_cleanup(self):
        """Emergency cleanup of all registered plugins and hanging processes."""
        with self._shutdown_lock:
            # Stop all registered plugins
            for plugin in list(self._active_plugins):
                try:
                    if hasattr(plugin, 'stop_capture'):
                        plugin.stop_capture()
                except Exception as e:
                    logger.debug(f"Error stopping plugin during emergency cleanup: {e}")
            
            # Force kill hanging scapy processes
            self._kill_hanging_processes()
    
    def _kill_hanging_processes(self):
        """Kill any hanging scapy or sniffing processes."""
        try:
            current_pid = os.getpid()
            
            # Look for potential hanging processes
            patterns = [
                "python.*sniff",
                "scapy",
                "tcpdump",
                "wireshark"
            ]
            
            for pattern in patterns:
                try:
                    result = subprocess.run(
                        ["pgrep", "-f", pattern],
                        capture_output=True,
                        text=True,
                        timeout=2
                    )
                    
                    if result.stdout:
                        for pid_str in result.stdout.strip().split('\n'):
                            if pid_str.strip():
                                try:
                                    pid = int(pid_str.strip())
                                    if pid != current_pid:
                                        # Check if it's actually a child process we should kill
                                        try:
                                            # First try gentle termination
                                            os.kill(pid, signal.SIGTERM)
                                            time.sleep(0.1)
                                            # Then force kill if still alive
                                            os.kill(pid, signal.SIGKILL)
                                        except (ProcessLookupError, PermissionError):
                                            pass  # Process already dead or not ours
                                except ValueError:
                                    continue  # Invalid PID
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue  # pgrep not available or timeout
        except Exception as e:
            logger.debug(f"Error during hanging process cleanup: {e}")
    
    def force_kill_by_pid(self, pid: int):
        """Force kill a specific process by PID."""
        try:
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.1)
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass  # Process already dead or not accessible


# Global shutdown manager instance
shutdown_manager = ShutdownManager()


def register_for_cleanup(plugin):
    """Register a plugin for automatic cleanup on shutdown."""
    shutdown_manager.register_plugin(plugin)


def unregister_from_cleanup(plugin):
    """Unregister a plugin from automatic cleanup."""
    shutdown_manager.unregister_plugin(plugin)


def force_cleanup():
    """Force cleanup of all registered plugins and hanging processes."""
    shutdown_manager._emergency_cleanup()