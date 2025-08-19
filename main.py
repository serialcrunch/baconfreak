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
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
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
    interface: int = typer.Option(
        1, "--interface", "-i", help="🔗 Bluetooth HCI interface number", min=0
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
    🛰️  Start Bluetooth Low Energy packet scanning.

    This command begins monitoring BLE advertisements and categorizes devices
    by type (AirTags, AirPods, Tile trackers, etc.) and company identifiers.
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
    if timeout:
        config.set("bluetooth.scan_timeout", timeout)

    config.set("bluetooth.interface", interface)
    config.set("bluetooth.filter_duplicates", filter_duplicates)
    config.set("detection.min_rssi", min_rssi)

    # Show startup banner
    if not quiet:
        show_startup_banner(interface, config.output_dir_path, log_level)

    try:
        # Import and run scanner (avoid circular imports)
        from src.baconfreak import BluetoothScanner

        scanner = BluetoothScanner(
            interface=interface, enable_rich=not no_rich and not quiet, quiet=quiet
        )

        scanner.run()

    except KeyboardInterrupt:
        console.print("\n🛑 [yellow]Scan interrupted by user[/yellow]")
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


def show_startup_banner(interface: int, output_dir: Path, log_level: str):
    """Show startup banner with configuration."""
    banner = Panel.fit(
        f"🥓  [bold blue]baconfreak v1.0[/bold blue] - Bluetooth Analysis\n\n"
        f"🔗 Interface: [cyan]HCI{interface}[/cyan]\n"
        f"📁 Output: [cyan]{output_dir}[/cyan]\n"
        f"📝 Log Level: [cyan]{log_level}[/cyan]\n\n"
        f"[dim]Press Ctrl+C to stop scanning[/dim]",
        style="blue",
        title="🚀 Starting Scan",
    )
    console.print(banner)


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
