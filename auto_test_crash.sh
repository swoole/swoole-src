#!/bin/bash

export LD_LIBRARY_PATH=/usr/local/openssl35/lib64:/usr/local/openssl35/lib:/usr/local/lib

echo "========================================="
echo "Automated HTTP/3 Crash Test with GDB"
echo "========================================="

cd "$(dirname "$0")"

# Check if gdb is installed
if ! command -v gdb &> /dev/null; then
    echo "[ERROR] gdb is not installed."
    echo "Please install: sudo apt-get install gdb"
    exit 1
fi

# Create GDB commands that will:
# 1. Start the server
# 2. Wait 2 seconds
# 3. Send a QUIC packet from Python
# 4. Capture any crash
cat > /tmp/gdb_auto_test.txt <<'EOF'
set pagination off
set print pretty on
set breakpoint pending on

# Catch segfaults and aborts
handle SIGSEGV stop print nopass
handle SIGABRT stop print nopass

echo \n========================================\n
echo Starting HTTP/3 server in background...\n
echo ========================================\n\n

# Start the program
run &

# Give it time to start
shell sleep 2

# Send test packet
echo \nSending QUIC test packet...\n
shell python3 send_quic_initial.py 2>&1

# Wait a bit for crash
shell sleep 3

echo \n========================================\n
echo Checking if server is still running...\n
echo ========================================\n

# If we're here, either crashed or still running
quit
EOF

echo "[INFO] Starting automated test..."
echo ""

# Run in batch mode
gdb -batch -x /tmp/gdb_auto_test.txt \
    --args php -d extension=modules/swoole.so examples/http3_server.php 2>&1 | tee /tmp/gdb_output.log

echo ""
echo "========================================="
echo "Analysis:"
echo "========================================="

# Check for crash signatures in output
if grep -q "SIGSEGV\|SIGABRT\|Segmentation fault" /tmp/gdb_output.log; then
    echo "✗ CRASH DETECTED!"
    echo ""
    echo "Backtrace:"
    grep -A 30 "backtrace\|BACKTRACE" /tmp/gdb_output.log || echo "(No backtrace found)"
else
    echo "✓ No crash detected - server handled the packet"
fi

rm -f /tmp/gdb_auto_test.txt

echo ""
echo "Full log saved to: /tmp/gdb_output.log"
echo "========================================="
