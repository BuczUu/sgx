#!/bin/bash
# run.sh - Convenience script to start SGX PSI system with all components

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SGX_SDK=${SGX_SDK:-/home/marcel/sgx_lab/sgxsdk}

# Set up library path for SGX runtime
export LD_LIBRARY_PATH="${SGX_SDK}/lib64:${SCRIPT_DIR}/RemoteAttestation/sample_libcrypto:${LD_LIBRARY_PATH:-}"

echo "==================================="
echo "SGX PSI System - Auto-Launcher"
echo "==================================="
echo ""
echo "Library Path: $LD_LIBRARY_PATH"
echo "Working Directory: $SCRIPT_DIR"
echo ""

# Check if server binary exists
if [[ ! -f "$SCRIPT_DIR/server" ]]; then
    echo "ERROR: server binary not found at $SCRIPT_DIR/server"
    echo "Please build first: make clean && make"
    exit 1
fi

# Check if Python scripts exist
if [[ ! -f "$SCRIPT_DIR/data_server.py" ]]; then
    echo "ERROR: data_server.py not found"
    exit 1
fi

if [[ ! -f "$SCRIPT_DIR/receiver_client.py" ]]; then
    echo "ERROR: receiver_client.py not found"
    exit 1
fi

# Start server in background
echo "[1/3] Starting SGX Server on port 12345..."
"$SCRIPT_DIR/server" &
SERVER_PID=$!
sleep 2  # Give server time to start

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Shutting down..."
    kill $SERVER_PID 2>/dev/null || true
    kill $DATA_SERVER_1_PID 2>/dev/null || true
    kill $DATA_SERVER_2_PID 2>/dev/null || true
}

trap cleanup EXIT

# Start data servers
echo "[2/3] Starting Data Servers..."
python3 "$SCRIPT_DIR/data_server.py" --id 1 --data "Server1_Data: [Department A Sales Data]" &
DATA_SERVER_1_PID=$!
sleep 1

python3 "$SCRIPT_DIR/data_server.py" --id 2 --data "Server2_Data: [Department B Sales Data]" &
DATA_SERVER_2_PID=$!
sleep 1

# Run receiver client
echo "[3/3] Querying with Receiver Client..."
sleep 1
python3 "$SCRIPT_DIR/receiver_client.py"

echo ""
echo "Completed. Servers will shut down automatically."
