#!/bin/bash
# Baconfreak - Bluetooth Low Energy packet analysis tool helper script
# This script runs the baconfreak tool as sudo within the virtual environment

set -e  # Exit on any error

# Script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"

# Virtual environment paths to check (in order of preference)
VENV_PATHS=(
    "$PROJECT_ROOT/.venv"
    "$PROJECT_ROOT/venv"
    "$PROJECT_ROOT/.virtualenv"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;36m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Find virtual environment (cached)
VENV_PATH_CACHE=""
find_venv() {
    if [[ -n "$VENV_PATH_CACHE" ]]; then
        echo "$VENV_PATH_CACHE"
        return 0
    fi
    
    for venv_path in "${VENV_PATHS[@]}"; do
        if [[ -d "$venv_path" && -f "$venv_path/bin/python" ]]; then
            VENV_PATH_CACHE="$venv_path"
            echo "$venv_path"
            return 0
        fi
    done
    return 1
}

# Check if running as root
check_root() {
    [[ $EUID -eq 0 ]]
}

# Check if python3 is available
check_python() {
    command -v python3 >/dev/null 2>&1
}

# Get python version
get_python_version() {
    python3 --version | cut -d' ' -f2
}


# Show usage information
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS] [COMMAND] [ARGS...]

Baconfreak - Modern Bluetooth Low Energy and WiFi packet analysis tool

Commands:
  scan [OPTIONS]           Start BLE/WiFi packet scanning (default)
  doctor                   Run system diagnostics
  config-show             Show current configuration
  devices [OPTIONS]        Analyze captured devices
  --help, -h              Show this help message

Options:
  --interface, -i NUM     Bluetooth HCI interface number (default: 1)
  --timeout, -t SEC       Scan timeout in seconds (0 = infinite)
  --log-level, -l LEVEL   Logging level (DEBUG, INFO, WARNING, ERROR)
  --min-rssi NUM          Minimum RSSI threshold (default: -100)
  --output, -o DIR        Output directory for PCAP files
  --setup                 Setup virtual environment and dependencies
  --check                 Check system requirements without running

Examples:
  $0                                    # Start BLE scanning with default settings
  $0 scan -i 1 -l DEBUG               # Scan on HCI1 with debug logging
  $0 doctor                            # Run system diagnostics
  $0 --setup                           # Setup environment
  $0 --check                           # Check requirements

WiFi Plugin Requirements:
  - WiFi adapter with monitor mode support
  - Install WiFi tools: sudo apt install iw wireless-tools
  - Enable WiFi plugin in settings.toml: plugins.wifi.enabled = true

Project Structure:
  main.py                              # Modern CLI interface (Typer + Rich)
  src/baconfreak.py                    # Core Bluetooth scanner
  src/                                 # Business logic modules

Note: This tool requires root privileges.
EOF
}

# Setup virtual environment and dependencies
setup_environment() {
    log_info "Setting up baconfreak environment..."
    
    cd "$PROJECT_ROOT"
    
    # Check if python3 is available
    if ! check_python; then
        log_error "python3 not found. Please install Python 3.8 or later."
        exit 1
    fi
    
    # Create virtual environment if it doesn't exist
    if ! find_venv >/dev/null; then
        log_info "Creating virtual environment..."
        python3 -m venv .venv
        if [[ $? -ne 0 ]]; then
            log_error "Failed to create virtual environment"
            exit 1
        fi
    fi
    
    VENV_PATH=$(find_venv)
    log_info "Using virtual environment: $VENV_PATH"
    
    # Activate virtual environment and install dependencies
    source "$VENV_PATH/bin/activate"
    
    log_info "Installing/updating dependencies..."
    pip install --upgrade pip
    
    if [[ -f "$PROJECT_ROOT/pyproject.toml" ]]; then
        pip install -e ".[dev]"
    else
        log_error "No pyproject.toml found"
        exit 1
    fi
    
    log_success "Environment setup complete!"
    log_info "Project structure:"
    log_info "  main.py - Modern CLI interface"
    log_info "  src/ - Business logic modules"
    log_info "You can now run: $0 scan"
}

# Check system requirements
check_requirements() {
    log_info "Checking system requirements..."
    
    local errors=0
    
    # Check Python
    if check_python; then
        python_version=$(get_python_version)
        log_success "Python 3 found: $python_version"
    else
        log_error "Python 3 not found"
        errors=$((errors + 1))
    fi
    
    # Check virtual environment
    local venv_path
    if venv_path=$(find_venv); then
        log_success "Virtual environment found: $venv_path"
    else
        log_warning "Virtual environment not found - run with --setup"
        errors=$((errors + 1))
    fi
    
    # Check root privileges
    if check_root; then
        log_success "Running as root"
    else
        log_warning "Not running as root - Bluetooth access will require sudo"
    fi
    
    # Check Bluetooth tools
    if command -v hciconfig >/dev/null 2>&1; then
        log_success "Bluetooth tools found (hciconfig)"
    else
        log_warning "Bluetooth tools not found (hciconfig) - may need to install bluez"
    fi
    
    # Check WiFi tools (for WiFi plugin)
    local wifi_tools_found=0
    if command -v iw >/dev/null 2>&1; then
        log_success "WiFi tools found (iw)"
        wifi_tools_found=1
    fi
    if command -v iwconfig >/dev/null 2>&1; then
        log_success "WiFi tools found (iwconfig)"
        wifi_tools_found=1
    fi
    if [[ $wifi_tools_found -eq 0 ]]; then
        log_warning "WiFi tools not found (iw, iwconfig) - install with: sudo apt install iw wireless-tools"
        log_warning "WiFi plugin will not work without these tools"
    fi
    
    
    # Check if baconfreak files exist
    if [[ -f "$PROJECT_ROOT/main.py" ]]; then
        log_success "Baconfreak CLI found (main.py)"
    elif [[ -f "$PROJECT_ROOT/src/baconfreak.py" ]]; then
        log_success "Baconfreak core module found (src/baconfreak.py)"
    else
        log_error "Baconfreak scripts not found (main.py or src/baconfreak.py)"
        errors=$((errors + 1))
    fi
    
    # Check src directory structure
    if [[ -d "$PROJECT_ROOT/src" ]]; then
        log_success "Source directory found"
        # Check for key modules
        local missing_modules=()
        for module in config.py models.py device_detector.py logger.py company_identifiers.py; do
            if [[ ! -f "$PROJECT_ROOT/src/$module" ]]; then
                missing_modules+=("$module")
            fi
        done
        
        if [[ ${#missing_modules[@]} -eq 0 ]]; then
            log_success "All core modules found in src/"
        else
            log_warning "Missing modules in src/: ${missing_modules[*]}"
        fi
    else
        log_error "Source directory (src/) not found"
        errors=$((errors + 1))
    fi
    
    if [[ $errors -eq 0 ]]; then
        log_success "All requirements satisfied!"
        return 0
    else
        log_error "$errors requirement(s) not satisfied"
        return 1
    fi
}

# Main execution function
run_baconfreak() {
    # Find virtual environment
    VENV_PATH=$(find_venv)
    if [[ -z "$VENV_PATH" ]]; then
        log_error "Virtual environment not found!"
        log_info "Run '$0 --setup' to create the environment"
        exit 1
    fi
    
    log_info "Using virtual environment: $VENV_PATH"
    
    # Determine which script to run (prefer main.py)
    local python_script=""
    if [[ -f "$PROJECT_ROOT/main.py" ]]; then
        python_script="$PROJECT_ROOT/main.py"
        log_info "Using main CLI interface: main.py"
    else
        log_error "No main.py found!"
        exit 1
    fi
    
    # Check if we need sudo for this command
    local needs_sudo=false
    case "${1:-scan}" in
        scan)
            needs_sudo=true
            ;;
        doctor|config-show|devices|--help|-h|--version)
            needs_sudo=false
            ;;
        *)
            # For unknown commands, assume sudo is needed
            needs_sudo=true
            ;;
    esac
    
    if [[ "$needs_sudo" == "true" ]] && ! check_root; then
        log_info "Requesting sudo privileges for Bluetooth access..."
        # Pass the current arguments through sudo, preserving the environment
        exec sudo -E PYTHONPATH="$PROJECT_ROOT" "$VENV_PATH/bin/python" "$python_script" "$@"
    else
        # Run directly (either no sudo needed, or already root)
        cd "$PROJECT_ROOT"
        PYTHONPATH="$PROJECT_ROOT" "$VENV_PATH/bin/python" "$python_script" "$@"
    fi
}

# Parse command line arguments
main() {
    # Handle special flags first
    case "${1:-}" in
        --help|-h)
            show_usage
            exit 0
            ;;
        --setup)
            setup_environment
            exit 0
            ;;
        --check)
            check_requirements
            exit $?
            ;;
        "")
            # No arguments, default to scan
            run_baconfreak scan
            ;;
        *)
            # Pass all arguments to baconfreak
            run_baconfreak "$@"
            ;;
    esac
}

# Ensure we're in the right directory
cd "$PROJECT_ROOT" || exit 1

# Run main function with all arguments
main "$@"