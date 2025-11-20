#!/bin/bash

export LD_LIBRARY_PATH=/usr/local/openssl35/lib64:/usr/local/openssl35/lib:/usr/local/lib

echo "========================================="
echo "HTTP/3 Server GDB Debugger"
echo "========================================="

cd "$(dirname "$0")"

# Check if gdb is installed
if ! command -v gdb &> /dev/null; then
    echo "[ERROR] gdb is not installed."
    echo "Please install: apt-get install gdb"
    exit 1
fi

echo "[INFO] This script will:"
echo "  1. Start HTTP/3 server under GDB"
echo "  2. Wait for you to send an HTTP/3 request"
echo "  3. Capture crash information if it happens"
echo ""
echo "Press Enter to continue..."
read

# Create GDB commands
cat > /tmp/gdb_http3_commands.txt <<'EOF'
set pagination off
set print pretty on

# Enable pending breakpoints (for shared libraries not yet loaded)
set breakpoint pending on

# Handle signals
handle SIGSEGV stop print nopass
handle SIGABRT stop print nopass

# Start the program and let it run until it hits a signal or exits
echo \n========================================\n
echo Starting HTTP/3 server...\n
echo Server will run until crash or Ctrl+C\n
echo Send your HTTP/3 request from another terminal\n
echo ========================================\n\n

run

# If we get here, the program crashed or exited
echo \n\n========================================\n
echo Program stopped. Analyzing...\n
echo ========================================\n

# Check if program is still running
if $_siginfo
  echo \nSignal received: $_siginfo\n
end

echo \n========================================\n
echo BACKTRACE:\n
echo ========================================\n
backtrace full

echo \n========================================\n
echo REGISTERS:\n
echo ========================================\n
info registers

echo \n========================================\n
echo THREADS:\n
echo ========================================\n
info threads

echo \n========================================\n
echo LOCAL VARIABLES (current frame):\n
echo ========================================\n
info locals

echo \n========================================\n
echo ARGUMENTS (current frame):\n
echo ========================================\n
info args

quit
EOF

echo "[INFO] Starting HTTP/3 server under GDB..."
echo "[INFO] The server will automatically show backtrace if it crashes."
echo ""

gdb -batch -x /tmp/gdb_http3_commands.txt \
    --args php -d extension=modules/swoole.so examples/http3_server.php

rm -f /tmp/gdb_http3_commands.txt

echo ""
echo "========================================="
echo "GDB session ended"
echo "========================================="
