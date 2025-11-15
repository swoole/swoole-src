#!/bin/bash
set -e

echo "========================================="
echo "Swoole HTTP/3 Complete Rebuild and Test"
echo "========================================="

cd "$(dirname "$0")"

echo "[Step 1] Cleaning previous build..."
make clean 2>/dev/null || true
phpize --clean 2>/dev/null || true
rm -rf .libs autom4te.cache build config.h* config.log config.nice config.status \
       configure* include/config.h* libtool Makefile* modules run-tests.php

echo "[Step 2] Running phpize..."
phpize

echo "[Step 3] Configuring with HTTP/3 support..."
./configure \
    --with-openssl-dir=/usr/local/openssl35 \
    --enable-swoole-quic \
    --enable-swoole-http3 \
    --enable-debug

echo "[Step 4] Building..."
make clean
make -j$(nproc)

echo "[Step 5] Installing extension..."
make install || sudo make install

echo ""
echo "========================================="
echo "[INFO] Build completed successfully!"
echo "========================================="

echo ""
echo "[Step 6] Testing HTTP/3 server..."
export LD_LIBRARY_PATH=/usr/local/openssl35/lib64:/usr/local/openssl35/lib:/usr/local/lib

# Run with detailed output
echo "Starting HTTP/3 server (will auto-stop after 5 seconds)..."
timeout 5 php -d extension=swoole.so examples/http3_server.php 2>&1 || {
    EXIT_CODE=$?
    if [ $EXIT_CODE -eq 124 ]; then
        echo ""
        echo "========================================="
        echo "[SUCCESS] Server ran for 5 seconds without crashing!"
        echo "========================================="
    else
        echo ""
        echo "========================================="
        echo "[ERROR] Server crashed with exit code: $EXIT_CODE"
        echo "========================================="
        exit 1
    fi
}
