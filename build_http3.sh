#!/bin/bash

# Automated build script for Swoole with HTTP/3 support
# This script will install all dependencies and compile Swoole

set -e  # Exit on any error

echo "========================================"
echo "Swoole HTTP/3 Build Script"
echo "========================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root for dependency installation
check_sudo() {
    if [ "$EUID" -ne 0 ]; then
        print_warn "This script requires sudo privileges to install system dependencies"
        print_info "You may be prompted for your password"
    fi
}

# Step 1: Install system dependencies
install_system_deps() {
    print_info "Installing system dependencies..."

    apt-get update
    apt-get install -y \
        build-essential \
        autoconf \
        automake \
        autotools-dev \
        libtool \
        pkg-config \
        libssl-dev \
        php-dev \
        php-cli \
        git \
        wget \
        cmake

    print_info "System dependencies installed"
}

# Step 2: Build and install QuicTLS (OpenSSL with QUIC support)
build_quictls() {
    print_info "Building QuicTLS (OpenSSL with QUIC support)..."

    cd /tmp
    rm -rf openssl

    # Clone QuicTLS (OpenSSL 3.3.0 with QUIC patches - latest stable)
    git clone --depth 1 --branch openssl-3.3.0+quic https://github.com/quictls/openssl.git
    cd openssl

    # Configure and build
    ./config --prefix=/usr/local/quictls \
        --openssldir=/usr/local/quictls

    make -j$(nproc)
    make install

    print_info "QuicTLS installed successfully to /usr/local/quictls"
}

# Step 3: Build and install ngtcp2
build_ngtcp2() {
    print_info "Building ngtcp2 (QUIC library)..."

    cd /tmp
    rm -rf ngtcp2

    git clone --depth 1 --branch v1.16.0 https://github.com/ngtcp2/ngtcp2.git
    cd ngtcp2

    autoreconf -i

    # Configure with QuicTLS and CFLAGS to avoid assembler .base64 issues
    PKG_CONFIG_PATH=/usr/local/quictls/lib64/pkgconfig:/usr/local/quictls/lib/pkgconfig:$PKG_CONFIG_PATH \
    CFLAGS="-O2 -g0" \
    LDFLAGS="-Wl,-rpath,/usr/local/quictls/lib64 -Wl,-rpath,/usr/local/quictls/lib" \
    ./configure --prefix=/usr/local \
        --with-openssl=/usr/local/quictls \
        --enable-lib-only

    make -j$(nproc)
    make install

    print_info "ngtcp2 installed successfully"
}

# Step 4: Build and install nghttp3
build_nghttp3() {
    print_info "Building nghttp3 (HTTP/3 library)..."

    cd /tmp
    rm -rf nghttp3

    # Clone nghttp3 (NOT with --depth 1 to allow submodule init)
    git clone --branch v1.12.0 https://github.com/ngtcp2/nghttp3.git
    cd nghttp3

    # Initialize git submodules (includes sfparse)
    git submodule update --init --recursive

    autoreconf -i

    # Configure with CFLAGS to avoid assembler .base64 issues
    CFLAGS="-O2 -g0" ./configure --prefix=/usr/local \
        --enable-lib-only

    make -j$(nproc)
    make install

    print_info "nghttp3 installed successfully"
}

# Step 5: Update library cache
update_ldconfig() {
    print_info "Updating library cache..."
    ldconfig
}

# Step 6: Verify libraries
verify_libraries() {
    print_info "Verifying library installation..."

    if pkg-config --exists ngtcp2; then
        print_info "ngtcp2 $(pkg-config --modversion ngtcp2) found"
    else
        print_error "ngtcp2 not found!"
        exit 1
    fi

    if pkg-config --exists libnghttp3; then
        print_info "nghttp3 $(pkg-config --modversion libnghttp3) found"
    else
        print_error "nghttp3 not found!"
        exit 1
    fi
}

# Step 7: Build Swoole
build_swoole() {
    print_info "Building Swoole with HTTP/3 support..."

    cd /home/user/swoole-src

    # Clean previous builds
    make clean 2>/dev/null || true
    phpize --clean 2>/dev/null || true

    # Run phpize
    phpize

    # Configure
    ./configure \
        --enable-swoole \
        --enable-openssl \
        --enable-http2 \
        --with-ngtcp2-dir=/usr/local \
        --with-nghttp3-dir=/usr/local

    # Compile
    make -j$(nproc)

    # Install
    make install

    print_info "Swoole compiled and installed successfully"
}

# Step 8: Enable Swoole extension
enable_extension() {
    print_info "Enabling Swoole extension..."

    PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
    CONF_DIR="/etc/php/${PHP_VERSION}/cli/conf.d"

    if [ -d "$CONF_DIR" ]; then
        echo "extension=swoole.so" | tee "${CONF_DIR}/20-swoole.ini"
        print_info "Extension enabled in ${CONF_DIR}/20-swoole.ini"
    else
        print_warn "Could not find PHP config directory"
        print_warn "Please manually add 'extension=swoole.so' to your php.ini"
    fi
}

# Step 9: Verify installation
verify_installation() {
    print_info "Verifying Swoole installation..."

    if php -m | grep -q swoole; then
        print_info "Swoole extension loaded"
    else
        print_error "Swoole extension not loaded!"
        exit 1
    fi

    if php -r 'exit(defined("SWOOLE_USE_HTTP3") && SWOOLE_USE_HTTP3 ? 0 : 1);'; then
        print_info "HTTP/3 support enabled!"
    else
        print_error "HTTP/3 support not enabled!"
        exit 1
    fi

    # Show Swoole version
    SWOOLE_VERSION=$(php -r 'echo phpversion("swoole");')
    print_info "Swoole version: ${SWOOLE_VERSION}"
}

# Main execution
main() {
    echo ""
    print_info "Starting build process..."
    echo ""

    check_sudo

    # Execute all steps
    install_system_deps
    echo ""

    build_quictls
    echo ""

    build_ngtcp2
    echo ""

    build_nghttp3
    echo ""

    update_ldconfig
    echo ""

    verify_libraries
    echo ""

    build_swoole
    echo ""

    enable_extension
    echo ""

    verify_installation
    echo ""

    echo "========================================"
    print_info "Build completed successfully!"
    echo "========================================"
    echo ""
    print_info "You can now run the HTTP/3 server example:"
    echo "  cd examples"
    echo "  php http3_server.php"
    echo ""
}

# Run main function
main
