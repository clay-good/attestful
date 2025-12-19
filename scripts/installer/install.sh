#!/usr/bin/env bash
#
# Attestful Offline Installation Script
#
# This script installs Attestful from a bundled tarball without network access.
# It handles Python version detection and bundle extraction.
#
# Usage:
#   ./install.sh [bundle.tar.gz] [--user|--prefix PATH]
#
# Examples:
#   ./install.sh attestful-bundle.tar.gz --user
#   ./install.sh attestful-bundle.tar.gz --prefix /opt/attestful
#   sudo ./install.sh attestful-bundle.tar.gz

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default values
BUNDLE_PATH=""
INSTALL_MODE="system"
INSTALL_PREFIX=""
PYTHON_CMD=""
TEMP_DIR=""
CLEANUP_TEMP=true

# Print colored message
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Cleanup function
cleanup() {
    if [ "$CLEANUP_TEMP" = true ] && [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
}
trap cleanup EXIT

# Show usage
usage() {
    cat << EOF
Attestful Offline Installation Script

Usage:
    $(basename "$0") BUNDLE [OPTIONS]

Arguments:
    BUNDLE              Path to attestful-bundle.tar.gz

Options:
    --user              Install to user site-packages
    --prefix PATH       Install to custom prefix
    --python PATH       Path to Python executable
    --no-init           Skip Attestful initialization
    --keep-temp         Keep temporary extraction directory
    -h, --help          Show this help message

Examples:
    $(basename "$0") attestful-bundle.tar.gz --user
    sudo $(basename "$0") attestful-bundle.tar.gz
    $(basename "$0") attestful-bundle.tar.gz --prefix /opt/attestful

EOF
}

# Detect Python
detect_python() {
    local required_version="3.11"

    # Check common Python commands
    for cmd in python3.12 python3.11 python3 python; do
        if command -v "$cmd" &> /dev/null; then
            local version
            version=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null)

            if [ -n "$version" ]; then
                local major minor
                major=$(echo "$version" | cut -d. -f1)
                minor=$(echo "$version" | cut -d. -f2)

                if [ "$major" -eq 3 ] && [ "$minor" -ge 11 ]; then
                    PYTHON_CMD="$cmd"
                    print_info "Found Python $version at: $(command -v "$cmd")"
                    return 0
                fi
            fi
        fi
    done

    print_error "Python 3.11+ not found"
    print_info "Please install Python 3.11 or higher and try again"
    return 1
}

# Parse arguments
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --user)
                INSTALL_MODE="user"
                shift
                ;;
            --prefix)
                INSTALL_MODE="prefix"
                INSTALL_PREFIX="$2"
                shift 2
                ;;
            --python)
                PYTHON_CMD="$2"
                shift 2
                ;;
            --no-init)
                NO_INIT=true
                shift
                ;;
            --keep-temp)
                CLEANUP_TEMP=false
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -*)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                if [ -z "$BUNDLE_PATH" ]; then
                    BUNDLE_PATH="$1"
                else
                    print_error "Unexpected argument: $1"
                    usage
                    exit 1
                fi
                shift
                ;;
        esac
    done

    if [ -z "$BUNDLE_PATH" ]; then
        print_error "Bundle path required"
        usage
        exit 1
    fi
}

# Verify bundle exists
verify_bundle() {
    if [ ! -f "$BUNDLE_PATH" ]; then
        print_error "Bundle not found: $BUNDLE_PATH"
        exit 1
    fi

    print_info "Using bundle: $BUNDLE_PATH"
}

# Extract bundle
extract_bundle() {
    TEMP_DIR=$(mktemp -d)
    print_info "Extracting bundle to: $TEMP_DIR"

    # Detect compression type
    case "$BUNDLE_PATH" in
        *.tar.gz|*.tgz)
            tar -xzf "$BUNDLE_PATH" -C "$TEMP_DIR"
            ;;
        *.tar.bz2|*.tbz2)
            tar -xjf "$BUNDLE_PATH" -C "$TEMP_DIR"
            ;;
        *.tar.xz)
            tar -xJf "$BUNDLE_PATH" -C "$TEMP_DIR"
            ;;
        *.tar)
            tar -xf "$BUNDLE_PATH" -C "$TEMP_DIR"
            ;;
        *)
            print_error "Unknown archive format"
            exit 1
            ;;
    esac

    # Find extracted directory
    BUNDLE_DIR=$(find "$TEMP_DIR" -maxdepth 1 -type d -name "attestful*" | head -1)

    if [ -z "$BUNDLE_DIR" ] || [ ! -d "$BUNDLE_DIR" ]; then
        print_error "Invalid bundle structure"
        exit 1
    fi

    print_success "Bundle extracted successfully"
}

# Run Python installer
run_installer() {
    local installer="$BUNDLE_DIR/install.py"

    if [ ! -f "$installer" ]; then
        print_error "Installer not found in bundle"
        exit 1
    fi

    print_info "Running Python installer..."

    # Build command
    local cmd=("$PYTHON_CMD" "$installer")

    case "$INSTALL_MODE" in
        user)
            cmd+=("--user")
            ;;
        prefix)
            cmd+=("--prefix" "$INSTALL_PREFIX")
            ;;
    esac

    if [ "${NO_INIT:-false}" = true ]; then
        cmd+=("--no-init")
    fi

    # Run installer
    "${cmd[@]}"
}

# Main
main() {
    echo ""
    echo "=========================================="
    echo "  Attestful Offline Installer"
    echo "=========================================="
    echo ""

    parse_args "$@"
    verify_bundle

    # Detect Python if not specified
    if [ -z "$PYTHON_CMD" ]; then
        detect_python
    fi

    # Verify Python command works
    if ! "$PYTHON_CMD" --version &> /dev/null; then
        print_error "Python command not working: $PYTHON_CMD"
        exit 1
    fi

    extract_bundle
    run_installer

    echo ""
    print_success "Installation complete!"
    echo ""
    echo "To get started, run: attestful --help"
    echo ""
}

main "$@"
