#!/bin/bash
# Full integration test - Receiver + SGX Server + 2 Data Servers (C#)

set -e

echo "============================================"
echo "PSI_SGX Full Integration Test"
echo "============================================"
echo ""

cd /home/marcel/sgx_lab/examples/PSI_SGX

# Kill any lingering processes
echo "[SETUP] Cleaning up old processes..."
killall -9 dotnet server_ratls python3 2>/dev/null || true
sleep 2

# 1. Start DataServer1
echo "[1/4] Starting Data Server 1 (C#, port 9001)..."
dotnet run --project DataServer1 > /tmp/ds1.log 2>&1 &
DS1=$!
sleep 2

# 2. Start DataServer2
echo "[2/4] Starting Data Server 2 (C#, port 9002)..."
dotnet run --project DataServer2 > /tmp/ds2.log 2>&1 &
DS2=$!
sleep 2

# 3. Start SGX Server
echo "[3/4] Starting SGX Server (port 12345)..."
export SGX_SDK=/home/marcel/sgx_lab/sgxsdk
export SGX_MODE=SIM
export LD_LIBRARY_PATH=$SGX_SDK/lib64:$LD_LIBRARY_PATH
./server_ratls > /tmp/sgx_server.log 2>&1 &
SGX=$!
sleep 3

# 4. Run Receiver Client
echo "[4/4] Running Receiver Client..."
echo ""
echo "============================================"
echo "RECEIVER CLIENT - Make 3 FETCH requests"
echo "============================================"
python3 receiver_client.py << 'EOF'
FETCH
FETCH
FETCH
QUIT
EOF

echo ""
echo "============================================"
echo "TEST COMPLETED"
echo "============================================"
echo ""

# Cleanup
echo "[CLEANUP] Shutting down..."
kill -9 $DS1 $DS2 $SGX 2>/dev/null || true
sleep 1

echo ""
echo "=== DATA SERVER 1 LOG ==="
tail -20 /tmp/ds1.log 2>/dev/null | head -10

echo ""
echo "=== DATA SERVER 2 LOG ==="
tail -20 /tmp/ds2.log 2>/dev/null | head -10

echo ""
echo "=== SGX SERVER LOG (OCALL section) ==="
grep -A 5 -B 5 "ecall_receiver_request\|OCALL" /tmp/sgx_server.log 2>/dev/null | tail -40 || echo "(Log not available)"

echo ""
echo "[TEST] All done!"
