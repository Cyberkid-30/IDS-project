#!/bin/bash
#
# IDS Backend Startup Script
#
# This script starts the IDS backend with proper privileges
# for packet capture on Linux systems.
#
# Usage:
#   ./scripts/start_ids.sh [--dev]
#
# Options:
#   --dev    Run in development mode with auto-reload
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"

echo "=========================================="
echo "  IDS Backend Startup Script"
echo "=========================================="

# Check if running as root
check_privileges() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}Warning: Not running as root.${NC}"
        echo "Packet capture requires root privileges or CAP_NET_RAW capability."
        echo ""
        echo "Options:"
        echo "  1. Run with sudo: sudo ./scripts/start_ids.sh"
        echo "  2. Set capability: sudo setcap cap_net_raw+ep \$(which python3)"
        echo ""
        
        # Check for CAP_NET_RAW
        PYTHON_PATH=$(which python3)
        if getcap "$PYTHON_PATH" 2>/dev/null | grep -q "cap_net_raw"; then
            echo -e "${GREEN}CAP_NET_RAW capability detected on Python.${NC}"
        else
            echo -e "${RED}No CAP_NET_RAW capability. Detection may fail.${NC}"
        fi
    else
        echo -e "${GREEN}Running with root privileges.${NC}"
    fi
}

# Check Python version
check_python() {
    PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
    MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
    MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
    
    if [ "$MAJOR" -lt 3 ] || ([ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 10 ]); then
        echo -e "${RED}Error: Python 3.10+ required. Found: $PYTHON_VERSION${NC}"
        exit 1
    fi
    echo -e "${GREEN}Python version: $PYTHON_VERSION${NC}"
}

# Check virtual environment
check_venv() {
    if [ -z "$VIRTUAL_ENV" ]; then
        if [ -d "$PROJECT_DIR/venv" ]; then
            echo "Activating virtual environment..."
            source "$PROJECT_DIR/venv/bin/activate"
        elif [ -d "$PROJECT_DIR/.venv" ]; then
            echo "Activating virtual environment..."
            source "$PROJECT_DIR/.venv/bin/activate"
        else
            echo -e "${YELLOW}Warning: No virtual environment detected.${NC}"
        fi
    fi
}

# Install dependencies if needed
check_dependencies() {
    if [ -f "$PROJECT_DIR/requirements.txt" ]; then
        echo "Checking dependencies..."
        pip install -q -r "$PROJECT_DIR/requirements.txt"
    fi
}

# Initialize database and load signatures
init_database() {
    echo "Initializing database..."
    cd "$PROJECT_DIR"
    python3 -c "from app.database.init_db import init_database; init_database()"
    
    echo "Loading signatures..."
    python3 scripts/load_signatures.py
}

# Start the server
start_server() {
    cd "$PROJECT_DIR"
    
    if [ "$1" == "--dev" ]; then
        echo ""
        echo -e "${GREEN}Starting IDS in DEVELOPMENT mode...${NC}"
        echo ""
        exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
    else
        echo ""
        echo -e "${GREEN}Starting IDS in PRODUCTION mode...${NC}"
        echo ""
        exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1
    fi
}

# Main
main() {
    echo ""
    check_privileges
    echo ""
    check_python
    check_venv
    check_dependencies
    echo ""
    init_database
    echo ""
    start_server "$1"
}

main "$@"
