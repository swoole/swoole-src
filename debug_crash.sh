#!/bin/bash

echo "========================================="
echo "HTTP/3 Server Crash Debugger"
echo "========================================="

cd "$(dirname "$0")"

export LD_LIBRARY_PATH=/usr/local/openssl35/lib64:/usr/local/openssl35/lib:/usr/local/lib

# Check if gdb is installed
if ! command -v gdb &> /dev/null; then
    echo "[ERROR] gdb is not installed. Please install it first:"
    echo "  sudo apt-get install gdb"
    exit 1
fi

echo "[INFO] Running HTTP/3 server under GDB..."
echo "[INFO] When it crashes, you'll see a backtrace."
echo ""

# Create GDB commands file
cat > /tmp/gdb_commands.txt <<'EOF'
set pagination off
run
backtrace full
info registers
quit
EOF

# Run under GDB
gdb -batch -x /tmp/gdb_commands.txt --args php -d extension=swoole.so examples/http3_server.php

echo ""
echo "========================================="
echo "[INFO] Please share the output above"
echo "========================================="

rm -f /tmp/gdb_commands.txt
