#!/bin/bash

set -e

echo "========================================="
echo "Building curl with HTTP/3 support"
echo "========================================="

# Check dependencies
echo "[1/7] Checking build dependencies..."
if ! command -v git &> /dev/null || ! command -v autoconf &> /dev/null; then
    echo "Installing build dependencies..."
    sudo apt-get update
    sudo apt-get install -y build-essential autoconf automake libtool pkg-config git
fi

# Verify ngtcp2 and nghttp3 are installed
echo "[2/7] Verifying ngtcp2 and nghttp3..."
if ! pkg-config --exists libngtcp2; then
    echo "ERROR: libngtcp2 not found. Please ensure ngtcp2 is installed."
    exit 1
fi

if ! pkg-config --exists libnghttp3; then
    echo "ERROR: libnghttp3 not found. Please ensure nghttp3 is installed."
    exit 1
fi

echo "✓ ngtcp2 version: $(pkg-config --modversion libngtcp2)"
echo "✓ nghttp3 version: $(pkg-config --modversion libnghttp3)"

# Clone curl
CURL_DIR="/tmp/curl-http3-build"
echo "[3/7] Cloning curl repository..."
if [ -d "$CURL_DIR" ]; then
    echo "Removing existing directory..."
    rm -rf "$CURL_DIR"
fi

git clone --depth 1 https://github.com/curl/curl.git "$CURL_DIR"
cd "$CURL_DIR"

# Configure curl
echo "[4/7] Configuring curl with HTTP/3 support..."
autoreconf -fi

./configure \
    --prefix=/usr/local \
    --with-openssl=/usr/local/openssl35 \
    --with-ngtcp2=/usr/local \
    --with-nghttp3=/usr/local \
    --enable-alt-svc \
    --with-ca-bundle=/etc/ssl/certs/ca-certificates.crt

# Build
echo "[5/7] Building curl (this may take a few minutes)..."
make -j$(nproc)

# Install
echo "[6/7] Installing curl..."
sudo make install

# Verify installation
echo "[7/7] Verifying installation..."
/usr/local/bin/curl --version

echo ""
echo "========================================="
echo "✓ curl with HTTP/3 support installed!"
echo "========================================="
echo ""
echo "Location: /usr/local/bin/curl"
echo ""

# Check HTTP/3 support
if /usr/local/bin/curl --version | grep -q "HTTP3"; then
    echo "✓ HTTP/3 support: ENABLED"
else
    echo "⚠ Warning: HTTP/3 support may not be enabled"
    echo "Please check the output above for any errors"
fi

echo ""
echo "You can now test with:"
echo "  /usr/local/bin/curl --http3-only -k https://localhost:443/"
echo ""
echo "Or add to PATH:"
echo "  export PATH=/usr/local/bin:\$PATH"
echo "  curl --http3-only -k https://localhost:443/"
