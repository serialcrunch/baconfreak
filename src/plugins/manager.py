"""
Plugin manager for coordinating capture plugins.
"""

import queue
import signal
import sys
import threading
import time
from typing import Any, Dict, Optional

from loguru import logger
from rich.console import Console
from rich.live import Live
from rich.panel import Panel

from .base import CapturePlugin, PluginError
from .registry import plugin_registry


class PluginManager:
    """
    Manages plugin lifecycle and coordinates capture operations.
    """

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.active_plugin: Optional[CapturePlugin] = None
        self._running = False
        self._stop_event = threading.Event()
        self._capture_thread: Optional[threading.Thread] = None
        self._keyboard_thread: Optional[threading.Thread] = None
        self._exit_message = None  # Store exit message to display in TUI

        # Set up signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum: int, frame: Any):
        """Handle shutdown signals gracefully."""
        if not self._running:
            # Already shutting down, force exit
            self._exit_message = "🔥 [red]Force quitting...[/red]"
            logger.warning("Second signal received, forcing exit...")
            import sys

            sys.exit(0)

        # Show immediate feedback that Ctrl+C was detected
        self._exit_message = "🛑 [yellow]Exiting...[/yellow]"
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop()

    def list_available_plugins(self) -> Dict[str, Any]:
        """List all available plugins with their information."""
        return plugin_registry.list_all_plugins()

    def create_plugin(self, protocol: str, config: Dict[str, Any]) -> CapturePlugin:
        """
        Create and validate a plugin instance.

        Args:
            protocol: Protocol name (e.g., 'ble', 'wifi')
            config: Plugin configuration

        Returns:
            Configured plugin instance

        Raises:
            PluginError: If plugin creation or validation fails
        """
        plugin = plugin_registry.create_plugin(protocol, config, self.console)
        if not plugin:
            raise PluginError(f"Unknown protocol: {protocol}")

        # Validate configuration
        valid, errors = plugin.validate_config()
        if not valid:
            raise PluginError(f"Plugin configuration invalid: {'; '.join(errors)}")

        # Check requirements
        req_met, req_errors = plugin.check_requirements()
        if not req_met:
            raise PluginError(f"Plugin requirements not met: {'; '.join(req_errors)}")

        return plugin

    def start_capture(
        self, plugin: CapturePlugin, enable_ui: bool = True, quiet: bool = False
    ) -> None:
        """
        Start capture with the specified plugin.

        Args:
            plugin: Plugin instance to use for capture
            enable_ui: Enable Rich UI
            quiet: Quiet mode
        """
        self.active_plugin = plugin
        self._running = True
        self._stop_event.clear()

        try:
            # Initialize plugin
            plugin.initialize_capture()

            # Show startup info
            if not quiet:
                self._show_startup_info(plugin)

            if enable_ui and not quiet:
                self._run_with_ui(plugin)
            else:
                self._run_simple(plugin, quiet)

        except Exception as e:
            logger.error(f"Capture failed: {e}")
            raise PluginError(f"Capture failed: {e}")
        finally:
            self._cleanup()

    def stop(self):
        """Stop the current capture session."""
        self._running = False
        self._stop_event.set()

        if self.active_plugin:
            try:
                self.active_plugin.stop_capture()
            except Exception as e:
                logger.error(f"Error stopping plugin: {e}")

        # Wait for threads to finish
        self._join_threads()

        # Force cleanup if needed
        self._force_cleanup()

    def _join_threads(self):
        """Wait for background threads to finish."""
        threads_to_join = []

        if self._capture_thread and self._capture_thread.is_alive():
            threads_to_join.append(("capture", self._capture_thread))

        if self._keyboard_thread and self._keyboard_thread.is_alive():
            threads_to_join.append(("keyboard", self._keyboard_thread))

        for thread_name, thread in threads_to_join:
            try:
                logger.debug(f"Waiting for {thread_name} thread to finish...")
                thread.join(timeout=2.0)  # Wait up to 2 seconds
                if thread.is_alive():
                    logger.warning(f"{thread_name} thread didn't finish cleanly")
                else:
                    logger.debug(f"{thread_name} thread finished successfully")
            except Exception as e:
                logger.error(f"Error joining {thread_name} thread: {e}")

    def _show_startup_info(self, plugin: CapturePlugin):
        """Show startup information."""
        info = plugin.info
        stats = plugin.get_statistics()

        startup_panel = Panel.fit(
            f"🚀 [bold blue]Starting {info.name}[/bold blue]\n\n"
            f"Protocol: [cyan]{info.protocol.upper()}[/cyan]\n"
            f"Version: [cyan]{info.version}[/cyan]\n"
            f"Description: [dim]{info.description}[/dim]\n\n"
            f"[dim]Press Ctrl+C to stop[/dim]",
            style="blue",
            title="🎯 Plugin Startup",
        )
        self.console.print(startup_panel)

    def _run_with_ui(self, plugin: CapturePlugin):
        """Run capture with Rich UI."""
        layout = plugin.create_live_display()

        with Live(layout, refresh_per_second=2, console=self.console) as live:
            # Start capture in background thread
            self._capture_thread = threading.Thread(
                target=self._capture_worker, args=(plugin,), daemon=True
            )
            self._capture_thread.start()

            # Keyboard input handling
            key_queue = queue.Queue()
            self._keyboard_thread = threading.Thread(
                target=self._keyboard_worker, args=(key_queue,), daemon=True
            )
            self._keyboard_thread.start()

            # Update display loop
            while self._running and self._capture_thread.is_alive():
                # Always do normal display update
                plugin.update_display(layout)

                # Handle keyboard input
                try:
                    while True:
                        key = key_queue.get_nowait()
                        if hasattr(plugin, "handle_keyboard_input"):
                            plugin.handle_keyboard_input(key)
                except queue.Empty:
                    pass

                time.sleep(0.5)

    def _run_simple(self, plugin: CapturePlugin, quiet: bool):
        """Run capture in simple mode without UI."""
        if not quiet:
            self.console.print("Starting packet capture... (Press Ctrl+C to stop)")

        self._capture_worker(plugin)

    def _capture_worker(self, plugin: CapturePlugin):
        """Worker thread for packet capture."""
        try:

            def packet_callback(device_info, packet):
                # Plugin handles the packet internally
                pass

            plugin.start_capture(packet_callback, self._stop_event)
        except KeyboardInterrupt:
            # Let KeyboardInterrupt propagate to signal handlers
            logger.debug("KeyboardInterrupt in capture worker, propagating...")
            raise
        except Exception as e:
            logger.error(f"Capture worker error: {e}")
            self.stop()

    def _keyboard_worker(self, key_queue: queue.Queue):
        """Worker thread for keyboard input."""
        import select
        import termios
        import tty

        stdin_fd = sys.stdin.fileno()
        old_settings = None

        try:
            old_settings = termios.tcgetattr(stdin_fd)
            new_settings = termios.tcgetattr(stdin_fd)
            new_settings[3] = new_settings[3] & ~(termios.ECHO | termios.ICANON)
            new_settings[6][termios.VMIN] = 1
            new_settings[6][termios.VTIME] = 0
            termios.tcsetattr(stdin_fd, termios.TCSADRAIN, new_settings)

            while self._running:
                try:
                    ready, _, _ = select.select([sys.stdin], [], [], 0.1)

                    if ready and self._running:
                        key = sys.stdin.read(1)
                        if key:
                            # Let signal handlers handle Ctrl+C (ASCII 3)
                            # Only process regular keys here
                            if ord(key) != 3:
                                key_queue.put(key)
                except (KeyboardInterrupt, EOFError):
                    self.stop()
                    break
                except Exception:
                    continue
        except Exception:
            pass
        finally:
            if old_settings is not None:
                try:
                    termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_settings)
                except Exception:
                    pass

    def _cleanup(self):
        """Cleanup resources."""
        self._running = False

        if self.active_plugin:
            try:
                self.active_plugin.stop_capture()
            except Exception as e:
                logger.error(f"Error during plugin cleanup: {e}")

        self.active_plugin = None

    def _force_cleanup(self):
        """Force cleanup of hanging processes."""
        import os
        import signal
        import subprocess

        try:
            # Find and kill any hanging scapy processes
            current_pid = os.getpid()

            # Look for python processes that might be hanging
            try:
                result = subprocess.run(
                    ["pgrep", "-f", "python.*sniff"], capture_output=True, text=True, timeout=2
                )

                if result.stdout:
                    for pid_str in result.stdout.strip().split("\n"):
                        if pid_str.strip():
                            pid = int(pid_str.strip())
                            if pid != current_pid:
                                try:
                                    # First try gentle termination
                                    os.kill(pid, signal.SIGTERM)
                                    time.sleep(0.5)
                                    # Then force kill if still alive
                                    os.kill(pid, signal.SIGKILL)
                                except (ProcessLookupError, PermissionError):
                                    pass  # Process already dead or permission denied
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass  # pgrep not available or timeout
        except Exception as e:
            logger.debug(f"Force cleanup error (non-critical): {e}")

    def get_session_summary(self) -> Optional[Dict[str, Any]]:
        """Get summary of the current/last session."""
        if not self.active_plugin:
            return None

        return {
            "plugin_info": self.active_plugin.info.dict(),
            "statistics": self.active_plugin.get_statistics(),
            "session_timestamp": self.active_plugin.session_timestamp,
        }
