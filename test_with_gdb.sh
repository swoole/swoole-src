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

# Set breakpoints at critical locations
break swoole::quic::Server::accept_connection
break swoole::quic::Connection::recv_packet
break swoole::http3::Connection::init_server
break swoole::http3::Connection::open_control_streams

# Handle signals
handle SIGSEGV stop print
handle SIGABRT stop print

# Display helpful info on breakpoint
commands 1
  echo \n=== accept_connection called ===\n
  continue
end

commands 2
  echo \n=== recv_packet called ===\n
  continue
end

commands 3
  echo \n=== HTTP/3 init_server called ===\n
  continue
end

commands 4
  echo \n=== open_control_streams called ===\n
  continue
end

echo \n========================================\n
echo Server is ready. Send your HTTP/3 request now.\n
echo If it crashes, backtrace will be displayed.\n
echo ========================================\n\n

run

# If we get here, either the program ended normally or crashed
echo \n\n========================================\n
echo CRASH DETECTED - Backtrace:\n
echo ========================================\n
backtrace full

echo \n========================================\n
echo Register dump:\n
echo ========================================\n
info registers

echo \n========================================\n
echo Thread information:\n
echo ========================================\n
info threads

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
