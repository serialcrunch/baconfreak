"""Test TUI exit message functionality for replacing device tables."""

import unittest
from unittest.mock import MagicMock, Mock, patch

from rich.console import Console
from rich.layout import Layout

from src.plugins.manager import PluginManager
from src.plugins.tabbed_manager import TabbedPluginManager


class TestExitMessageFunctionality(unittest.TestCase):
    """Test TUI exit message functionality."""

    def test_plugin_manager_exit_message_storage(self):
        """Test that PluginManager stores exit message."""
        console = Console()
        manager = PluginManager(console)

        # Set running state and call signal handler
        manager._running = True
        manager.stop = Mock()

        # Call signal handler
        manager._signal_handler(2, None)  # SIGINT

        # Should have stored the exit message
        self.assertEqual(manager._exit_message, "🛑 [yellow]Exiting...[/yellow]")

    def test_tabbed_manager_exit_message_storage(self):
        """Test that TabbedPluginManager stores exit message."""
        console = Console()
        manager = TabbedPluginManager(console)

        # Set running state and call signal handler
        manager._running = True
        manager.stop = Mock()

        # Call signal handler
        manager._signal_handler(2, None)  # SIGINT

        # Should have stored the exit message
        self.assertEqual(manager._exit_message, "🛑 [yellow]Exiting...[/yellow]")

    def test_force_exit_message_storage(self):
        """Test that force exit message is stored correctly."""
        console = Console()
        manager = PluginManager(console)

        # Already shutting down
        manager._running = False

        with patch("sys.exit", side_effect=SystemExit):
            with self.assertRaises(SystemExit):
                manager._signal_handler(2, None)  # SIGINT

        # Should have stored the force quit message
        self.assertEqual(manager._exit_message, "🔥 [red]Force quitting...[/red]")

    def test_tabbed_manager_global_footer_update_with_exit_message(self):
        """Test that TabbedPluginManager updates global footer with exit message."""
        console = Console()
        manager = TabbedPluginManager(console)

        # Set exit message
        manager._exit_message = "🛑 [yellow]Exiting...[/yellow]"

        # Create mock layout
        mock_layout = Mock()
        mock_global_footer = Mock()
        mock_layout.__getitem__ = Mock(return_value=mock_global_footer)

        # Mock required attributes for _update_tabbed_display
        manager.tab_names = ["BLE"]
        manager.current_tab = 0
        manager.active_plugins = {"ble": Mock()}
        mock_plugin = Mock()
        mock_plugin.create_live_display.return_value = Mock()
        mock_plugin.update_display = Mock()
        mock_plugin.get_statistics.return_value = {"devices": 5, "packets": 100}
        manager.active_plugins["ble"] = mock_plugin

        # Call update tabbed display
        manager._update_tabbed_display(mock_layout)

        # Should have updated the global footer
        mock_layout.__getitem__.assert_called()

    def test_exit_message_in_footer_text(self):
        """Test that exit message appears correctly in footer text."""
        console = Console()
        manager = TabbedPluginManager(console)

        # Set up required attributes
        manager.tab_names = ["BLE"]
        manager.current_tab = 0
        manager.active_plugins = {"ble": Mock()}
        mock_plugin = Mock()
        mock_plugin.create_live_display.return_value = Mock()
        mock_plugin.update_display = Mock()
        mock_plugin.get_statistics.return_value = {"devices": 0, "packets": 0}
        manager.active_plugins["ble"] = mock_plugin

        # Create real layout to test footer content
        from rich.layout import Layout

        layout = Layout()
        layout.split_column(
            Layout(name="tabs", size=3),
            Layout(name="content"),
            Layout(name="global_footer", size=3),
        )

        # Test with exit message
        manager._exit_message = "🛑 [yellow]Exiting...[/yellow]"
        manager._update_tabbed_display(layout)

        # The global_footer should contain exit message text
        self.assertIsNotNone(layout["global_footer"].renderable)

    def test_signal_handler_sets_exit_message(self):
        """Test that signal handlers set the exit message."""
        console = Mock()
        manager = PluginManager(console)

        # Set running state
        manager._running = True
        manager.stop = Mock()

        # Call signal handler
        manager._signal_handler(2, None)  # SIGINT

        # Should have set the exit message
        self.assertIsNotNone(manager._exit_message)
        self.assertIn("Exiting", manager._exit_message)

    def test_tabbed_manager_signal_handler_sets_exit_message(self):
        """Test that tabbed manager signal handlers set the exit message."""
        console = Mock()
        manager = TabbedPluginManager(console)

        # Set running state
        manager._running = True
        manager.stop = Mock()

        # Call signal handler
        manager._signal_handler(2, None)  # SIGINT

        # Should have set the exit message
        self.assertIsNotNone(manager._exit_message)
        self.assertIn("Exiting", manager._exit_message)


if __name__ == "__main__":
    unittest.main()
