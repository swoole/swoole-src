#!/bin/bash

set -e

echo "========================================="
echo "Building curl with HTTP/3 support"
echo "Using OpenSSL 3.5 native QUIC"
echo "========================================="

# Check dependencies
echo "[1/6] Checking build dependencies..."
if ! command -v git &> /dev/null || ! command -v autoconf &> /dev/null; then
    echo "Installing build dependencies..."
    apt-get update
    apt-get install -y build-essential autoconf automake libtool pkg-config git
fi

# Verify OpenSSL 3.5 and nghttp3 are installed
echo "[2/6] Verifying OpenSSL 3.5 and nghttp3..."
if [ ! -f /usr/local/openssl35/bin/openssl ]; then
    echo "ERROR: OpenSSL 3.5 not found at /usr/local/openssl35"
    exit 1
fi

if ! pkg-config --exists libnghttp3; then
    echo "ERROR: libnghttp3 not found. Please ensure nghttp3 is installed."
    exit 1
fi

echo "✓ OpenSSL version: $(LD_LIBRARY_PATH=/usr/local/openssl35/lib64:/usr/local/openssl35/lib /usr/local/openssl35/bin/openssl version)"
echo "✓ nghttp3 version: $(pkg-config --modversion libnghttp3)"

# Clone curl
CURL_DIR="/tmp/curl-http3-openssl-build"
echo "[3/6] Cloning curl repository..."
if [ -d "$CURL_DIR" ]; then
    echo "Removing existing directory..."
    rm -rf "$CURL_DIR"
fi

git clone --depth 1 https://github.com/curl/curl.git "$CURL_DIR"
cd "$CURL_DIR"

# Configure curl
echo "[4/6] Configuring curl with HTTP/3 support (OpenSSL QUIC)..."
autoreconf -fi

export PKG_CONFIG_PATH=/usr/local/openssl35/lib64/pkgconfig:/usr/local/openssl35/lib/pkgconfig:/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
export LDFLAGS="-Wl,-rpath,/usr/local/openssl35/lib64 -Wl,-rpath,/usr/local/openssl35/lib -L/usr/local/openssl35/lib64 -L/usr/local/openssl35/lib"

./configure \
    --prefix=/usr/local/curl-http3 \
    --with-openssl=/usr/local/openssl35 \
    --with-openssl-quic \
    --with-nghttp3=/usr/local \
    --enable-alt-svc \
    --without-libpsl \
    --without-zstd \
    --with-ca-bundle=/etc/ssl/certs/ca-certificates.crt

# Build
echo "[5/6] Building curl (this may take a few minutes)..."
make -j$(nproc)

# Install
echo "[6/6] Installing curl..."
make install

# Create symlink
ln -sf /usr/local/curl-http3/bin/curl /usr/local/bin/curl-http3

# Verify installation
echo ""
echo "========================================="
echo "Verifying installation..."
echo "========================================="
LD_LIBRARY_PATH=/usr/local/openssl35/lib64:/usr/local/openssl35/lib:/usr/local/lib /usr/local/curl-http3/bin/curl --version

echo ""
echo "========================================="
echo "✓ curl with HTTP/3 support installed!"
echo "========================================="
echo ""
echo "Location: /usr/local/curl-http3/bin/curl"
echo "Symlink: /usr/local/bin/curl-http3"
echo ""

# Check HTTP/3 support
if LD_LIBRARY_PATH=/usr/local/openssl35/lib64:/usr/local/openssl35/lib /usr/local/curl-http3/bin/curl --version | grep -q "HTTP3\|QUIC"; then
    echo "✓ HTTP/3 support: ENABLED"
else
    echo "⚠ Warning: HTTP/3 support may not be enabled"
    echo "Please check the output above for any errors"
fi

echo ""
echo "You can now test with:"
echo "  LD_LIBRARY_PATH=/usr/local/openssl35/lib64:/usr/local/openssl35/lib curl-http3 --http3-only -k https://localhost:443/"
echo ""
