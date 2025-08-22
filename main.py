"""
CLI interface using Typer and Rich.
"""

import sys
from pathlib import Path
from typing import List, Optional

import typer
from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress, 
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from src.config import config
from src.logger import setup_logging
from src.models import DeviceType

app = typer.Typer(
    name="baconfreak",
    help="🥓  Bluetooth Low Energy packet analysis tool",
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console()


def version_callback(value: bool):
    """Show version information."""
    if value:
        console.print("🥓  [bold blue]baconfreak[/bold blue] - Bluetooth Analysis Tool")
        console.print("Version: [green]1.0.0[/green]")
        console.print("Built with: [cyan]Scapy, Pydantic, Loguru, Rich, Typer[/cyan]")
        raise typer.Exit()


def config_callback(value: Optional[str]):
    """Load custom configuration file."""
    if value:
        config_path = Path(value)
        if not config_path.exists():
            console.print(f"❌ Configuration file not found: {config_path}", style="red")
            raise typer.Exit(1)
        logger.info(f"Loading configuration from: {config_path}")


@app.command()
def scan(
    protocols: List[str] = typer.Option(
        ["ble", "wifi"], "--protocol", "-p", help="📡 Capture protocols (ble, wifi, etc.) - can specify multiple"
    ),
    ble_interface: Optional[str] = typer.Option(
        None, "--ble-interface", help="🔗 BLE HCI interface (e.g., hci0, hci1) - overrides config file"
    ),
    wifi_interface: Optional[str] = typer.Option(
        None, "--wifi-interface", help="📶 WiFi interface name - overrides config file"
    ),
    timeout: int = typer.Option(
        0, "--timeout", "-t", help="⏱️  Scan timeout in seconds (0 = infinite)", min=0
    ),
    output_dir: Optional[Path] = typer.Option(
        None, "--output", "-o", help="📁 Output directory for PCAP files", exists=False
    ),
    log_level: str = typer.Option(
        "INFO", "--log-level", "-l", help="📝 Logging level", case_sensitive=False
    ),
    log_file: Optional[Path] = typer.Option(None, "--log-file", help="📄 Log file path"),
    min_rssi: int = typer.Option(
        -100, "--min-rssi", help="📶 Minimum RSSI threshold (dBm)", min=-127, max=20
    ),
    filter_duplicates: bool = typer.Option(
        False,
        "--filter-duplicates/--no-filter-duplicates",
        help="🔄 Filter duplicate advertisements",
    ),
    wifi_channels: Optional[str] = typer.Option(
        "1,6,11", "--wifi-channels", help="📡 WiFi channels to scan (comma-separated)"
    ),
    channel_hop: bool = typer.Option(
        True, "--channel-hop/--no-channel-hop", help="🔄 Enable WiFi channel hopping"
    ),
    tabbed: bool = typer.Option(
        None, "--tabbed/--no-tabbed", help="📊 Use tabbed interface (auto-enabled for multiple protocols)"
    ),
    enable_plugin: Optional[List[str]] = typer.Option(
        None, "--enable-plugin", help="🔌 Force enable specific plugins (overrides config)"
    ),
    disable_plugin: Optional[List[str]] = typer.Option(
        None, "--disable-plugin", help="🚫 Force disable specific plugins (overrides config)"
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="🤫 Quiet mode (minimal output)"),
    no_rich: bool = typer.Option(False, "--no-rich", help="🎨 Disable Rich formatting"),
    config_file: Optional[str] = typer.Option(
        None, "--config", "-c", help="⚙️  Configuration file path", callback=config_callback
    ),
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        help="📋 Show version information",
        callback=version_callback,
        is_eager=True,
    ),
):
    """
    🛰️  Start network packet scanning with pluggable protocols.

    This command begins monitoring network packets using the specified protocols
    (BLE, WiFi, etc.) and categorizes devices by type and company identifiers.
    Supports multiple protocols simultaneously with a tabbed interface.
    """

    # Setup logging
    use_tui = not no_rich and not quiet
    bt_logger = setup_logging(
        level=log_level.upper(),
        log_file=str(log_file) if log_file else None,
        enable_rich=use_tui,
        tui_mode=use_tui,
    )

    # Update configuration with CLI parameters
    if output_dir:
        config.set("paths.output_dir", str(output_dir))

    # Auto-enable tabbed interface for multiple protocols
    if tabbed is None:
        use_tabbed = len(protocols) > 1
    else:
        use_tabbed = tabbed

    try:
        # Import plugin framework
        from src.plugins import plugin_registry
        
        if use_tabbed:
            from src.plugins.tabbed_manager import TabbedPluginManager
            manager = TabbedPluginManager(console)
        else:
            from src.plugins import PluginManager
            manager = PluginManager(console)

        # Check if all protocols are available
        available_protocols = plugin_registry.list_protocols()
        for protocol in protocols:
            if protocol not in available_protocols:
                available = ", ".join(available_protocols)
                console.print(f"❌ [red]Unknown protocol: {protocol}[/red]")
                console.print(f"💡 [blue]Available protocols: {available}[/blue]")
                raise typer.Exit(1)

        # Parse WiFi channels
        wifi_channel_list = []
        if wifi_channels:
            try:
                wifi_channel_list = [int(ch.strip()) for ch in wifi_channels.split(",")]
            except ValueError:
                console.print("❌ [red]Invalid WiFi channels format. Use comma-separated numbers like '1,6,11'[/red]")
                raise typer.Exit(1)

        # Configure and add plugins
        plugins_added = []
        
        for protocol in protocols:
            # Build protocol-specific configuration
            plugin_config = config.get_plugin_config(protocol)
            
            # Apply CLI enable/disable overrides
            if disable_plugin and protocol in disable_plugin:
                console.print(f"⚠️  [yellow]Protocol {protocol} force disabled via CLI - skipping[/yellow]")
                continue
            
            if enable_plugin and protocol in enable_plugin:
                # Force enable via CLI
                plugin_config["enabled"] = True
                console.print(f"🔌 [green]Protocol {protocol} force enabled via CLI[/green]")
            
            # Check if plugin is enabled in configuration
            if not plugin_config.get("enabled", True):  # Default to enabled if not specified
                console.print(f"⚠️  [yellow]Protocol {protocol} is disabled in configuration - skipping[/yellow]")
                continue
            
            if protocol == "ble":
                # Only override config values when CLI params are explicitly provided
                ble_overrides = {
                    "scan_timeout": timeout,
                    "filter_duplicates": filter_duplicates,
                    "min_rssi": min_rssi
                }
                if ble_interface is not None:
                    ble_overrides["interface"] = ble_interface
                plugin_config.update(ble_overrides)
            elif protocol == "wifi":
                # Only override config values when CLI params are explicitly provided
                wifi_overrides = {
                    "scan_timeout": timeout,
                    "channel_hop": channel_hop,
                    "min_rssi": min_rssi
                }
                if wifi_interface is not None:
                    wifi_overrides["interface"] = wifi_interface
                if wifi_channel_list:  # Only override if channels were specified
                    wifi_overrides["channels"] = wifi_channel_list
                plugin_config.update(wifi_overrides)
            else:
                # Generic configuration for other protocols
                plugin_config.update({
                    "scan_timeout": timeout,
                    "min_rssi": min_rssi
                })

            # Add plugin to manager
            if use_tabbed:
                plugin = manager.add_plugin(protocol, plugin_config)
            else:
                plugin = manager.create_plugin(protocol, plugin_config)
            
            plugins_added.append((protocol, plugin))

        # Check if any plugins were actually added
        if not plugins_added:
            console.print("❌ [red]No enabled plugins found![/red]")
            console.print("💡 [blue]Enable plugins in settings.toml or use different protocols[/blue]")
            raise typer.Exit(1)

        # Show startup banner
        if not quiet:
            if use_tabbed:
                show_tabbed_startup_banner(plugins_added, config.output_dir_path, log_level)
            else:
                protocol, plugin = plugins_added[0]
                show_startup_banner(protocol, plugin, config.output_dir_path, log_level)

        # Start capture
        if use_tabbed:
            manager.start_capture(enable_ui=not no_rich, quiet=quiet)
        else:
            # For single plugin, pass the plugin to start_capture
            _, plugin = plugins_added[0]
            manager.start_capture(plugin, enable_ui=not no_rich, quiet=quiet)

        # Show summary
        if not quiet:
            if use_tabbed:
                show_tabbed_session_summary(manager)
            else:
                show_session_summary(manager)

    except KeyboardInterrupt:
        # Signal handler already showed "Exiting..." message
        raise typer.Exit(0)
    except PermissionError:
        console.print("❌ [red]Permission denied - run with sudo[/red]")
        console.print("💡 [blue]Try: sudo python -m baconfreak scan[/blue]")
        raise typer.Exit(1)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        console.print(f"❌ [red]Scan failed: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def config_show():
    """
    ⚙️  Show current configuration.
    """
    console.print(Panel.fit("🔧 [bold]baconfreak Configuration[/bold]", style="blue"))

    # Create configuration table
    table = Table(show_header=True, header_style="bold blue")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Description", style="dim")

    # Core settings
    table.add_row("Interface", str(config.bluetooth_interface), "Bluetooth HCI interface")
    table.add_row("Output Dir", str(config.output_dir_path), "PCAP output directory")
    table.add_row("Log Level", config.log_level, "Logging verbosity")
    table.add_row("Scan Timeout", f"{config.scan_timeout}s", "Scan duration (0=infinite)")
    table.add_row("Filter Duplicates", str(config.filter_duplicates), "Advertisement filtering")
    table.add_row("DB Batch Size", str(config.db_batch_size), "Database bulk operations")

    console.print(table)

    # Show paths
    console.print(f"\n📁 [bold]Paths:[/bold]")
    paths_tree = Tree("🏠 Base Directory", style="bold blue")
    paths_tree.add(f"📤 Output: {config.output_dir_path}")
    paths_tree.add(f"🗄️  Assets: {config.assets_dir_path}")
    paths_tree.add(f"📋 Logs: {config.logs_dir_path}")
    paths_tree.add(f"⚙️  External: {config.external_dir_path}")

    console.print(paths_tree)


@app.command()
def devices(
    pcap_file: Optional[Path] = typer.Argument(None, help="📊 PCAP file to analyze"),
    device_type: Optional[List[DeviceType]] = typer.Option(
        None, "--type", "-t", help="🏷️  Filter by device type"
    ),
    min_rssi: int = typer.Option(-100, "--min-rssi", help="📶 Minimum RSSI threshold"),
    company: Optional[str] = typer.Option(
        None, "--company", "-c", help="🏢 Filter by company name"
    ),
    export_json: Optional[Path] = typer.Option(
        None, "--export-json", help="💾 Export results to JSON file"
    ),
):
    """
    📊 Analyze captured devices and show statistics.

    Parse PCAP files or show live device information with filtering options.
    """
    console.print(Panel.fit("📊 [bold]Device Analysis[/bold]", style="green"))

    if pcap_file and pcap_file.exists():
        # Analyze PCAP file
        analyze_pcap_file(pcap_file, device_type, min_rssi, company, export_json)
    else:
        # Show live device information
        show_device_summary()


@app.command()
def doctor():
    """
    🩺 Run system diagnostics and check configuration.
    """
    console.print(Panel.fit("🩺 [bold]baconfreak System Diagnostics[/bold]", style="cyan"))

    checks = [
        ("Python Version", check_python_version),
        ("Required Packages", check_packages),
        ("Bluetooth Interface", check_bluetooth_interface),
        ("Permissions", check_permissions),
        ("Output Directories", check_directories),
        ("Configuration", check_configuration),
    ]

    results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:

        task = progress.add_task("Running diagnostics...", total=len(checks))

        for name, check_func in checks:
            progress.update(task, description=f"Checking {name}...")
            result = check_func()
            results.append((name, result))
            progress.advance(task)

    # Show results
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Check", style="white")
    table.add_column("Status", style="white")
    table.add_column("Details", style="dim")

    for name, (status, details) in results:
        status_text = "✅ PASS" if status else "❌ FAIL"
        status_style = "green" if status else "red"
        table.add_row(name, Text(status_text, style=status_style), details)

    console.print(table)

    # Summary
    passed = sum(1 for _, (status, _) in results if status)
    total = len(results)

    if passed == total:
        console.print(f"\n🎉 [green]All checks passed! ({passed}/{total})[/green]")
    else:
        console.print(f"\n⚠️  [yellow]{passed}/{total} checks passed[/yellow]")


@app.command()
def plugins():
    """
    🔌 List available capture plugins.
    """
    try:
        from src.plugins import plugin_registry
        
        console.print(Panel.fit("🔌 [bold]Available Capture Plugins[/bold]", style="blue"))
        
        plugins_info = plugin_registry.list_all_plugins()
        
        if not plugins_info:
            console.print("❌ [red]No plugins available[/red]")
            return
        
        # Create plugins table
        table = Table(show_header=True, header_style="bold blue")
        table.add_column("Protocol", style="cyan", width=10)
        table.add_column("Name", style="green", width=15)
        table.add_column("Version", style="yellow", width=8)
        table.add_column("Description", style="white")
        table.add_column("Requires Root", style="red", width=12)
        table.add_column("Platforms", style="dim", width=12)
        
        for protocol, info in plugins_info.items():
            table.add_row(
                protocol.upper(),
                info.name,
                info.version,
                info.description,
                "Yes" if info.requires_root else "No",
                ", ".join(info.supported_platforms)
            )
        
        console.print(table)
        
        # Show usage example
        example_protocol = list(plugins_info.keys())[0]
        console.print(f"\n💡 [blue]Example usage:[/blue]")
        console.print(f"   baconfreak scan --protocol {example_protocol}")
        
        # Show plugin status
        console.print(f"\n📊 [blue]Plugin Status:[/blue]")
        for protocol in plugins_info.keys():
            plugin_config = config.get_plugin_config(protocol)
            enabled = plugin_config.get("enabled", True)
            status = "[green]Enabled[/green]" if enabled else "[red]Disabled[/red]"
            console.print(f"   {protocol.upper()}: {status}")
        
    except Exception as e:
        console.print(f"❌ [red]Failed to list plugins: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def update_db(
    force: bool = typer.Option(False, "--force", "-f", help="🔄 Force update even if files haven't changed")
):
    """🗃️  Update company identifiers database from YAML sources."""
    try:
        from src.company_identifiers import CompanyIdentifiers
        
        console.print("🗃️  [bold blue]Updating Company Identifiers Database[/bold blue]")
        console.print("Loading company identifiers...")
        
        ci = CompanyIdentifiers()
        
        with console.status("[bold blue]Updating database...", spinner="dots"):
            result = ci.update(force=force)
        
        if result["errors"]:
            console.print(f"❌ [red]Update failed with {len(result['errors'])} errors[/red]")
            for error in result["errors"]:
                console.print(f"   • {error}", style="red")
            raise typer.Exit(1)
        
        # Show results
        table = Table(title="Update Results")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Files Processed", str(result["files_processed"]))
        table.add_row("Records Loaded", str(result["records_loaded"]))
        table.add_row("Records Saved", str(result["records_saved"]))
        table.add_row("Duration", f"{result['duration']:.2f}s")
        
        console.print(table)
        
        if result["warnings"]:
            console.print(f"\n⚠️  [yellow]{len(result['warnings'])} warnings:[/yellow]")
            for warning in result["warnings"]:
                console.print(f"   • {warning}", style="yellow")
        
        console.print(f"\n✅ [green]Database updated successfully![/green]")
        console.print(f"Database location: [cyan]{config.company_identifiers_db_path}[/cyan]")
        
    except Exception as e:
        console.print(f"❌ [red]Failed to update database: {e}[/red]")
        logger.error(f"Database update failed: {e}")
        raise typer.Exit(1)


def show_startup_banner(protocol: str, plugin, output_dir: Path, log_level: str):
    """Show startup banner with plugin configuration."""
    info = plugin.info
    stats = plugin.get_statistics()
    
    banner = Panel.fit(
        f"🥓  [bold blue]baconfreak v1.0[/bold blue] - Network Analysis\n\n"
        f"📡 Protocol: [cyan]{protocol.upper()}[/cyan]\n"
        f"🔗 Interface: [cyan]{stats.get('interface', 'N/A')}[/cyan]\n"
        f"📁 Output: [cyan]{output_dir}[/cyan]\n"
        f"📝 Log Level: [cyan]{log_level}[/cyan]\n\n"
        f"[dim]{info.description}[/dim]\n"
        f"[dim]Press Ctrl+C to stop scanning[/dim]",
        style="blue",
        title="🚀 Starting Scan",
    )
    console.print(banner)


def show_session_summary(manager):
    """Show session summary after capture."""
    summary = manager.get_session_summary()
    if not summary:
        return
    
    stats = summary["statistics"]
    plugin_info = summary["plugin_info"]
    
    # Create summary table
    table = Table(show_header=True, header_style="bold green")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Protocol", plugin_info["protocol"].upper())
    table.add_row("Devices Found", str(stats.get("devices", 0)))
    table.add_row("Packets Captured", f"{stats.get('packets', 0):,}")
    table.add_row("Valid Packets", f"{stats.get('valid_packets', 0):,}")
    table.add_row("Packets/Second", f"{stats.get('packets_per_second', 0):.1f}")
    table.add_row("Error Rate", f"{stats.get('error_rate', 0):.2%}")
    
    console.print(Panel(table, title="📊 Session Summary", style="green"))
    
    # Show output files
    output_files = stats.get("output_files", {})
    if output_files:
        files_text = "📁 [bold]Output Files:[/bold]\n\n"
        for file_type, path in output_files.items():
            files_text += f"📤 {file_type.replace('_', ' ').title()}: [cyan]{path}[/cyan]\n"
        
        console.print(Panel(files_text, title="💾 Files", style="bright_blue"))


def show_tabbed_startup_banner(plugins_added, output_dir: Path, log_level: str):
    """Show startup banner for tabbed multi-protocol session."""
    banner_text = f"🥓  [bold blue]baconfreak v1.0[/bold blue] - Multi-Protocol Analysis\n\n"
    
    for protocol, plugin in plugins_added:
        info = plugin.info
        stats = plugin.get_statistics()
        banner_text += f"📡 {protocol.upper()}: [cyan]{info.name}[/cyan] on [cyan]{stats.get('interface', 'N/A')}[/cyan]\n"
    
    banner_text += f"\n📁 Output: [cyan]{output_dir}[/cyan]\n"
    banner_text += f"📝 Log Level: [cyan]{log_level}[/cyan]\n\n"
    banner_text += f"[dim]Use Tab/Shift+Tab to switch between protocols[/dim]\n"
    banner_text += f"[dim]Press 1-{len(plugins_added)} to jump to specific protocols[/dim]\n"
    banner_text += f"[dim]Press Ctrl+C to stop all scanning[/dim]"
    
    banner = Panel.fit(banner_text, style="blue", title="🚀 Starting Multi-Protocol Scan")
    console.print(banner)


def show_tabbed_session_summary(manager):
    """Show session summary for tabbed multi-protocol session."""
    summaries = manager.get_session_summary()
    if not summaries:
        return
    
    # Create overall summary table
    table = Table(show_header=True, header_style="bold green")
    table.add_column("Protocol", style="cyan")
    table.add_column("Devices", style="green", justify="right")
    table.add_column("Packets", style="green", justify="right")
    table.add_column("Valid Packets", style="green", justify="right")
    table.add_column("Rate (pkt/s)", style="green", justify="right")
    table.add_column("Error Rate", style="yellow", justify="right")
    
    total_devices = 0
    total_packets = 0
    total_valid = 0
    
    for protocol, summary in summaries.items():
        stats = summary["statistics"]
        devices = stats.get("devices", 0)
        packets = stats.get("packets", 0)
        valid_packets = stats.get("valid_packets", 0)
        rate = stats.get("packets_per_second", 0)
        error_rate = stats.get("error_rate", 0)
        
        table.add_row(
            protocol.upper(),
            str(devices),
            f"{packets:,}",
            f"{valid_packets:,}",
            f"{rate:.1f}",
            f"{error_rate:.2%}"
        )
        
        total_devices += devices
        total_packets += packets
        total_valid += valid_packets
    
    # Add totals row
    table.add_row(
        "[bold]TOTAL[/bold]",
        f"[bold]{total_devices}[/bold]",
        f"[bold]{total_packets:,}[/bold]",
        f"[bold]{total_valid:,}[/bold]",
        "[bold]-[/bold]",
        "[bold]-[/bold]"
    )
    
    console.print(Panel(table, title="📊 Multi-Protocol Session Summary", style="green"))
    
    # Show output files for each protocol
    for protocol, summary in summaries.items():
        stats = summary["statistics"]
        output_files = stats.get("output_files", {})
        
        if output_files:
            files_text = f"📁 [bold]{protocol.upper()} Output Files:[/bold]\n\n"
            for file_type, path in output_files.items():
                files_text += f"📤 {file_type.replace('_', ' ').title()}: [cyan]{path}[/cyan]\n"
            
            console.print(Panel(files_text, title=f"💾 {protocol.upper()} Files", style="bright_blue"))


def analyze_pcap_file(
    pcap_file: Path, device_types, min_rssi: int, company: str, export_json: Optional[Path]
):
    """Analyze a PCAP file and show device statistics."""
    console.print(f"📂 Analyzing: [cyan]{pcap_file}[/cyan]")
    # TODO: Implement PCAP analysis
    console.print("🚧 [yellow]PCAP analysis coming soon![/yellow]")


def show_device_summary():
    """Show live device summary."""
    console.print("📱 [yellow]Live device monitoring not implemented yet[/yellow]")
    console.print("💡 [blue]Use 'scan' command to start monitoring[/blue]")


# Diagnostic functions
def check_python_version() -> tuple[bool, str]:
    """Check Python version compatibility."""
    version = sys.version_info
    if version.major == 3 and version.minor >= 8:
        return True, f"Python {version.major}.{version.minor}.{version.micro}"
    else:
        return False, f"Python {version.major}.{version.minor} (requires 3.8+)"


def check_packages() -> tuple[bool, str]:
    """Check required packages."""
    try:
        import loguru
        import pydantic
        import rich
        import scapy

        return True, "All packages available"
    except ImportError as e:
        return False, f"Missing package: {e.name}"


def check_bluetooth_interface() -> tuple[bool, str]:
    """Check Bluetooth interface availability."""
    try:
        from scapy.layers.bluetooth import BluetoothHCISocket

        interface = config.bluetooth_interface
        # Try to create socket (may require permissions)
        try:
            bt = BluetoothHCISocket(interface)
            bt.close()
            return True, f"HCI{interface} available"
        except PermissionError:
            return False, f"HCI{interface} permission denied (need sudo)"
        except Exception as e:
            return False, f"HCI{interface} error: {e}"
    except ImportError:
        return False, "Scapy Bluetooth support not available"


def check_permissions() -> tuple[bool, str]:
    """Check required permissions."""
    import os

    if os.geteuid() == 0:
        return True, "Running as root"
    else:
        return False, "Root privileges required for Bluetooth access"


def check_directories() -> tuple[bool, str]:
    """Check output directories."""
    try:
        config.ensure_directories()
        return True, "All directories accessible"
    except Exception as e:
        return False, f"Directory error: {e}"


def check_configuration() -> tuple[bool, str]:
    """Check configuration validity."""
    try:
        scan_config = config.scan_config
        return True, f"Configuration valid (interface: {scan_config.interface})"
    except Exception as e:
        return False, f"Configuration error: {e}"


if __name__ == "__main__":
    app()
