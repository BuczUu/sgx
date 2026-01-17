#!/bin/bash
# Comprehensive integration test for PSI_SGX with Receiver + DataServers

set -e

echo "=== PSI_SGX Full Integration Test ==="
echo ""
echo "Starting all components..."

# Kill any existing processes
killall -9 server_ratls dotnet python3 2>/dev/null || true
sleep 1

cd /home/marcel/sgx_lab/examples/PSI_SGX

# 1. Start DataServer1 (C# on port 9001)
echo "[TEST] Starting Data Server 1 (C#, port 9001)..."
dotnet run --project DataServer1 > /tmp/dataserver1.log 2>&1 &
DS1_PID=$!
sleep 2

# 2. Start DataServer2 (C# on port 9002)
echo "[TEST] Starting Data Server 2 (C#, port 9002)..."
dotnet run --project DataServer2 > /tmp/dataserver2.log 2>&1 &
DS2_PID=$!
sleep 2

# 3. Start SGX Server
echo "[TEST] Starting SGX Server (port 12345)..."
export SGX_SDK=/home/marcel/sgx_lab/sgxsdk
export SGX_MODE=SIM
export LD_LIBRARY_PATH=$SGX_SDK/lib64:$LD_LIBRARY_PATH
./server_ratls > /tmp/sgx_server.log 2>&1 &
SGX_PID=$!
sleep 3

# 4. Run Receiver Client
echo "[TEST] Running Receiver Client..."
echo ""
echo "=== RECEIVER CLIENT OUTPUT ==="
python3 receiver_client.py << 'EOF'
FETCH
FETCH
QUIT
EOF

echo ""
echo "=== TEST COMPLETE ==="
echo ""

# Cleanup
echo "[TEST] Cleaning up..."
kill -9 $DS1_PID $DS2_PID $SGX_PID 2>/dev/null || true

# Show logs
echo ""
echo "=== Data Server 1 Log ==="
tail -20 /tmp/dataserver1.log

echo ""
echo "=== Data Server 2 Log ==="
tail -20 /tmp/dataserver2.log

echo ""
echo "=== SGX Server Log ==="
tail -40 /tmp/sgx_server.log

echo ""
echo "[TEST] Done!"
