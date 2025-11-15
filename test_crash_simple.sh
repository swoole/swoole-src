#!/bin/bash

export LD_LIBRARY_PATH=/usr/local/openssl35/lib64:/usr/local/openssl35/lib:/usr/local/lib

echo "========================================="
echo "Simple HTTP/3 Crash Test"
echo "========================================="

cd "$(dirname "$0")"

# Enable core dumps
ulimit -c unlimited
echo "Core dump size: $(ulimit -c)"

# Set core dump pattern
sudo sysctl -w kernel.core_pattern=/tmp/core-%e-%p-%t 2>/dev/null || \
    echo "[WARN] Could not set core dump pattern (need sudo)"

echo ""
echo "[1] Starting HTTP/3 server..."
php -d extension=modules/swoole.so examples/http3_server.php > /tmp/http3_test.log 2>&1 &
SERVER_PID=$!

sleep 2

# Check if started
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "✗ Server failed to start!"
    cat /tmp/http3_test.log
    exit 1
fi

echo "✓ Server started (PID: $SERVER_PID)"
echo ""
echo "[2] Sending QUIC Initial packet..."

python3 send_quic_initial.py

sleep 2

echo ""
echo "[3] Checking server status..."

if kill -0 $SERVER_PID 2>/dev/null; then
    echo "✓ Server is still running - NO CRASH"
    kill -9 $SERVER_PID 2>/dev/null

    echo ""
    echo "Server log:"
    cat /tmp/http3_test.log
    exit 0
else
    echo "✗ SERVER CRASHED!"

    # Check for core dump
    CORE_FILE=$(ls -t /tmp/core-php-* 2>/dev/null | head -1)

    if [ -n "$CORE_FILE" ]; then
        echo ""
        echo "Core dump found: $CORE_FILE"
        echo "Analyzing with GDB..."
        echo ""

        gdb -batch \
            -ex "set pagination off" \
            -ex "backtrace full" \
            -ex "info registers" \
            -ex "thread apply all backtrace" \
            php "$CORE_FILE" 2>&1 | tee /tmp/crash_analysis.txt

        echo ""
        echo "========================================="
        echo "Crash analysis saved to: /tmp/crash_analysis.txt"
        echo "========================================="
    else
        echo ""
        echo "No core dump found. Server log:"
        cat /tmp/http3_test.log
    fi

    exit 1
fi
