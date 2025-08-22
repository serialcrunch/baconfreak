"""
Tabbed plugin manager for coordinating multiple capture plugins with a tabbed TUI.
"""

import queue
import signal
import sys
import threading
import time
from typing import Any, Dict, List, Optional

from loguru import logger
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from .base import CapturePlugin, PluginError
from .registry import plugin_registry


class TabbedPluginManager:
    """
    Manages multiple plugins with a tabbed interface.
    """
    
    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.active_plugins: Dict[str, CapturePlugin] = {}
        self.current_tab = 0
        self.tab_names: List[str] = []
        self._running = False
        self._stop_event = threading.Event()
        self._capture_threads: Dict[str, threading.Thread] = {}
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
    
    def add_plugin(self, protocol: str, config: Dict[str, Any]) -> CapturePlugin:
        """
        Add a plugin to the manager.
        
        Args:
            protocol: Protocol name (e.g., 'ble', 'wifi')
            config: Plugin configuration
            
        Returns:
            Configured plugin instance
            
        Raises:
            PluginError: If plugin creation or validation fails
        """
        if protocol in self.active_plugins:
            raise PluginError(f"Plugin for protocol {protocol} already active")
        
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
        
        self.active_plugins[protocol] = plugin
        self.tab_names.append(protocol.upper())
        
        return plugin
    
    def remove_plugin(self, protocol: str):
        """Remove a plugin from the manager."""
        if protocol in self.active_plugins:
            plugin = self.active_plugins[protocol]
            try:
                plugin.stop_capture()
            except:
                pass
            
            del self.active_plugins[protocol]
            if protocol.upper() in self.tab_names:
                self.tab_names.remove(protocol.upper())
            
            # Adjust current tab if needed
            if self.current_tab >= len(self.tab_names):
                self.current_tab = max(0, len(self.tab_names) - 1)
    
    def get_current_plugin(self) -> Optional[CapturePlugin]:
        """Get the currently active plugin based on selected tab."""
        if not self.tab_names or self.current_tab >= len(self.tab_names):
            return None
        
        protocol = self.tab_names[self.current_tab].lower()
        return self.active_plugins.get(protocol)
    
    def switch_tab(self, direction: int):
        """Switch to next/previous tab."""
        if not self.tab_names:
            return
        
        self.current_tab = (self.current_tab + direction) % len(self.tab_names)
    
    def start_capture(self, enable_ui: bool = True, quiet: bool = False) -> None:
        """
        Start capture with all active plugins.
        
        Args:
            enable_ui: Enable Rich UI with tabs
            quiet: Quiet mode
        """
        if not self.active_plugins:
            raise PluginError("No plugins configured")
        
        self._running = True
        self._stop_event.clear()
        
        try:
            # Initialize all plugins
            for protocol, plugin in self.active_plugins.items():
                plugin.initialize_capture()
                logger.info(f"Initialized {protocol} plugin")
            
            # Show startup info
            if not quiet:
                self._show_startup_info()
            
            if enable_ui and not quiet:
                self._run_with_tabbed_ui()
            else:
                self._run_simple(quiet)
                
        except Exception as e:
            logger.error(f"Capture failed: {e}")
            raise PluginError(f"Capture failed: {e}")
        finally:
            self._cleanup()
    
    def stop(self):
        """Stop all capture sessions."""
        self._running = False
        self._stop_event.set()
        
        # Stop all plugins first
        for protocol, plugin in self.active_plugins.items():
            try:
                plugin.stop_capture()
                logger.info(f"Stopped {protocol} plugin")
            except Exception as e:
                logger.error(f"Error stopping {protocol} plugin: {e}")
        
        # Wait for capture threads to finish
        for protocol, thread in self._capture_threads.items():
            if thread.is_alive():
                logger.debug(f"Waiting for {protocol} capture thread to finish...")
                thread.join(timeout=3.0)
                if thread.is_alive():
                    logger.warning(f"{protocol} capture thread did not stop cleanly")
        
        # Force cleanup if needed
        self._force_cleanup()
    
    def _show_startup_info(self):
        """Show startup information for all plugins."""
        startup_text = "🚀 [bold blue]Starting Multi-Protocol Capture[/bold blue]\n\n"
        
        for protocol, plugin in self.active_plugins.items():
            info = plugin.info
            startup_text += f"📡 {protocol.upper()}: [cyan]{info.name} v{info.version}[/cyan]\n"
        
        startup_text += f"\n[dim]Active Protocols: {', '.join(self.tab_names)}[/dim]\n"
        startup_text += f"[dim]Use Tab/Shift+Tab to switch between protocols[/dim]\n"
        startup_text += f"[dim]Press Ctrl+C to stop[/dim]"
        
        startup_panel = Panel.fit(startup_text, style="blue", title="🎯 Multi-Plugin Startup")
        self.console.print(startup_panel)
    
    def _run_with_tabbed_ui(self):
        """Run capture with tabbed Rich UI."""
        layout = self._create_tabbed_layout()
        
        with Live(layout, refresh_per_second=2, console=self.console) as live:
            # Start capture for all plugins
            for protocol, plugin in self.active_plugins.items():
                thread = threading.Thread(
                    target=self._capture_worker,
                    args=(protocol, plugin),
                    daemon=True
                )
                thread.start()
                self._capture_threads[protocol] = thread
            
            # Keyboard input handling
            key_queue = queue.Queue()
            keyboard_thread = threading.Thread(
                target=self._keyboard_worker,
                args=(key_queue,),
                daemon=True
            )
            keyboard_thread.start()
            
            # Update display loop
            while self._running and any(t.is_alive() for t in self._capture_threads.values()):
                # Always do normal display update
                self._update_tabbed_display(layout)
                
                # Handle keyboard input
                try:
                    while True:
                        key = key_queue.get_nowait()
                        self._handle_global_keyboard_input(key)
                except queue.Empty:
                    pass
                
                time.sleep(0.5)
    
    def _run_simple(self, quiet: bool):
        """Run capture in simple mode without UI."""
        if not quiet:
            self.console.print("Starting multi-protocol packet capture... (Press Ctrl+C to stop)")
        
        # Start capture for all plugins
        for protocol, plugin in self.active_plugins.items():
            thread = threading.Thread(
                target=self._capture_worker,
                args=(protocol, plugin),
                daemon=True
            )
            thread.start()
            self._capture_threads[protocol] = thread
        
        # Wait for all threads to complete
        try:
            while self._running and any(t.is_alive() for t in self._capture_threads.values()):
                time.sleep(1.0)
        except KeyboardInterrupt:
            self.stop()
    
    def _capture_worker(self, protocol: str, plugin: CapturePlugin):
        """Worker thread for plugin packet capture."""
        try:
            def packet_callback(device_info, packet):
                # Plugin handles the packet internally
                pass
            
            plugin.start_capture(packet_callback, self._stop_event)
        except KeyboardInterrupt:
            # Let KeyboardInterrupt propagate to signal handlers
            logger.debug(f"KeyboardInterrupt in {protocol} capture worker, propagating...")
            raise
        except Exception as e:
            logger.error(f"Capture worker error for {protocol}: {e}")
            # Don't stop all plugins if one fails
    
    
    def _create_tabbed_layout(self) -> Layout:
        """Create tabbed layout structure."""
        layout = Layout()
        layout.split_column(
            Layout(name="tabs", size=3),
            Layout(name="content"),
            Layout(name="global_footer", size=3)
        )
        return layout
    
    def _update_tabbed_display(self, layout: Layout):
        """Update the tabbed display."""
        # Create tab bar
        tab_bar = self._create_tab_bar()
        layout["tabs"].update(tab_bar)
        
        # Update content for current tab
        current_plugin = self.get_current_plugin()
        if current_plugin:
            # Create plugin-specific layout
            plugin_layout = current_plugin.create_live_display()
            current_plugin.update_display(plugin_layout)
            layout["content"].update(plugin_layout)
        else:
            layout["content"].update(Panel("No plugin selected", style="red"))
        
        # Global footer - modify based on exit state
        if self._exit_message:
            # Show exit message instead of Ctrl+C
            if "Force quitting" in self._exit_message:
                exit_display = "[red]🔥 Force quitting...[/red]"
            else:
                exit_display = "[yellow]🛑 Exiting...[/yellow]"
            
            global_footer = Panel(
                "[dim]Global Controls: [/dim]"
                "[bright_blue]Tab[/bright_blue]=[dim]Next Plugin[/dim] | "
                "[bright_blue]Shift+Tab[/bright_blue]=[dim]Prev Plugin[/dim] | "
                "[bright_blue]1-9[/bright_blue]=[dim]Select Plugin[/dim] | "
                f"{exit_display}",
                style="dim"
            )
        else:
            # Normal footer with Ctrl+C
            global_footer = Panel(
                "[dim]Global Controls: [/dim]"
                "[bright_blue]Tab[/bright_blue]=[dim]Next Plugin[/dim] | "
                "[bright_blue]Shift+Tab[/bright_blue]=[dim]Prev Plugin[/dim] | "
                "[bright_blue]1-9[/bright_blue]=[dim]Select Plugin[/dim] | "
                "[red]Ctrl+C[/red]=[dim]Quit All[/dim]",
                style="dim"
            )
        layout["global_footer"].update(global_footer)
    
    def _create_tab_bar(self) -> Panel:
        """Create the tab bar showing all active plugins."""
        if not self.tab_names:
            return Panel("No plugins active", style="red")
        
        tab_text = Text()
        
        for i, tab_name in enumerate(self.tab_names):
            if i == self.current_tab:
                # Active tab
                tab_text.append(f" {tab_name} ", style="bold white on blue")
            else:
                # Inactive tab
                tab_text.append(f" {tab_name} ", style="white on black")
            
            if i < len(self.tab_names) - 1:
                tab_text.append(" ")
        
        
        return Panel(tab_text, style="bright_blue", height=3)
    
    def _handle_global_keyboard_input(self, key: str):
        """Handle global keyboard input for tab switching."""
        if key == '\t':  # Tab key
            self.switch_tab(1)
        elif key == '\x1b[Z':  # Shift+Tab (reverse tab)
            self.switch_tab(-1)
        elif key.isdigit():
            # Direct tab selection (1-9)
            tab_index = int(key) - 1
            if 0 <= tab_index < len(self.tab_names):
                self.current_tab = tab_index
        else:
            # Pass key to current plugin
            current_plugin = self.get_current_plugin()
            if current_plugin and hasattr(current_plugin, 'handle_keyboard_input'):
                current_plugin.handle_keyboard_input(key)
    
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
        
        # Stop all plugins
        for protocol, plugin in self.active_plugins.items():
            try:
                plugin.stop_capture()
            except Exception as e:
                logger.error(f"Error during {protocol} plugin cleanup: {e}")
        
        # Clear capture threads
        self._capture_threads.clear()
    
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
                    ["pgrep", "-f", "python.*sniff"],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                
                if result.stdout:
                    for pid_str in result.stdout.strip().split('\n'):
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
    
    def get_session_summary(self) -> Dict[str, Any]:
        """Get summary of all active sessions."""
        summaries = {}
        
        for protocol, plugin in self.active_plugins.items():
            summaries[protocol] = {
                "plugin_info": plugin.info.dict(),
                "statistics": plugin.get_statistics(),
                "session_timestamp": plugin.session_timestamp
            }
        
        return summaries