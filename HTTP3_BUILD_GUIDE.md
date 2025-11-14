# HTTP/3 Build and Installation Guide

This guide will help you compile Swoole with HTTP/3 support and run your first HTTP/3 server.

## Prerequisites

### Required Software

- **PHP 8.0+** with development headers
- **OpenSSL 3.0+** (required for QUIC/TLS 1.3)
- **ngtcp2 >= 1.16.0** (QUIC protocol implementation)
- **nghttp3 >= 1.12.0** (HTTP/3 protocol implementation)
- **Build tools**: gcc, g++, make, autoconf, libtool, pkg-config

### System Requirements

- Linux kernel 4.18+ (for optimal UDP performance)
- 64-bit system architecture

## Installation Steps

### Step 1: Install System Dependencies

#### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    autoconf \
    libtool \
    pkg-config \
    libssl-dev \
    php-dev \
    php-cli
```

### Step 2: Install ngtcp2 (QUIC Library)

```bash
# Download and build ngtcp2
cd /tmp
git clone --depth 1 --branch v1.16.0 https://github.com/ngtcp2/ngtcp2.git
cd ngtcp2

# Build with OpenSSL support
autoreconf -i

# Configure with CFLAGS to avoid assembler .base64 issues
CFLAGS="-O2 -g0" ./configure --prefix=/usr/local \
    --with-openssl \
    --enable-lib-only

make -j$(nproc)
sudo make install
```

### Step 3: Install sfparse (nghttp3 Dependency)

```bash
# Download and build sfparse
cd /tmp
git clone --depth 1 https://github.com/ngtcp2/sfparse.git
cd sfparse

autoreconf -i
CFLAGS="-O2 -g0" ./configure --prefix=/usr/local
make -j$(nproc)
sudo make install

# Manually create sfparse subdirectory and copy header
# nghttp3 expects sfparse/sfparse.h but sfparse installs to include/sfparse.h
sudo mkdir -p /usr/local/include/sfparse
sudo cp -f sfparse.h /usr/local/include/sfparse/
```

### Step 4: Install nghttp3 (HTTP/3 Library)

```bash
# Download and build nghttp3
cd /tmp
git clone --depth 1 --branch v1.12.0 https://github.com/ngtcp2/nghttp3.git
cd nghttp3

# Build
autoreconf -i

# Update library cache to ensure sfparse is found
sudo ldconfig

# Configure with environment variables to find sfparse headers and libraries
PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH \
CFLAGS="-O2 -g0" \
CPPFLAGS="-I/usr/local/include" \
LDFLAGS="-L/usr/local/lib" \
./configure --prefix=/usr/local \
    --enable-lib-only

make -j$(nproc)
sudo make install
```

### Step 5: Update Library Cache

```bash
sudo ldconfig
```

### Step 6: Verify Installation

```bash
# Check if libraries are installed
pkg-config --exists ngtcp2 && echo "ngtcp2 installed: $(pkg-config --modversion ngtcp2)"
pkg-config --exists libnghttp3 && echo "nghttp3 installed: $(pkg-config --modversion libnghttp3)"
```

### Step 7: Compile Swoole with HTTP/3 Support

```bash
# Navigate to Swoole source directory
cd /home/user/swoole-src

# Clean previous builds (if any)
make clean 2>/dev/null || true
phpize --clean

# Initialize build
phpize

# Configure with HTTP/3 support
./configure \
    --enable-swoole \
    --enable-openssl \
    --enable-http2 \
    --with-ngtcp2-dir=/usr/local \
    --with-nghttp3-dir=/usr/local

# Compile
make -j$(nproc)

# Install
sudo make install
```

### Step 8: Enable Swoole Extension

Add Swoole to your PHP configuration:

```bash
# Create swoole.ini
echo "extension=swoole.so" | sudo tee /etc/php/$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')/cli/conf.d/20-swoole.ini
```

### Step 9: Verify HTTP/3 Support

```bash
php -r 'var_dump(defined("SWOOLE_USE_HTTP3") && SWOOLE_USE_HTTP3);'
# Should output: bool(true)
```

## Running the HTTP/3 Server Example

### Generate SSL Certificate (for testing)

```bash
cd examples
./generate_ssl_cert.sh
```

### Start the Server

```bash
php examples/http3_server.php
```

### Test the Server

#### Using curl with HTTP/3

```bash
# Install curl with HTTP/3 support (if not already installed)
# On recent Ubuntu/Debian:
sudo apt-get install curl

# Test the server
curl --http3 -k https://localhost:443
```

#### Using Chrome/Edge (with HTTP/3 enabled)

1. Navigate to `chrome://flags/#enable-quic`
2. Enable "Experimental QUIC protocol"
3. Restart browser
4. Visit `https://localhost:443`
5. Accept the self-signed certificate warning
6. You should see: "hello from http3 server!"

## Troubleshooting

### Assembler `.base64` Error

**Error message:**
```
/tmp/ccXXXXXX.s: Assembler messages:
/tmp/ccXXXXXX.s:XXXX: Error: unknown pseudo-op: `.base64'
make: *** [Makefile:XXX: ngtcp2_XXX.lo] Error 1
```

**Cause:** Some compiler versions generate debug information in a format incompatible with the assembler.

**Solution:**
```bash
# Specify CFLAGS directly in configure command
CFLAGS="-O2 -g0" ./configure --prefix=/usr/local --with-openssl --enable-lib-only
make -j$(nproc)
```

**Important:** Use `CFLAGS=` directly before configure (not `export CFLAGS=`), as export may not work in sudo environments.

This fix is already included in the `build_http3.sh` script.

### Library Not Found Error

If you get library not found errors:

```bash
# Update library cache
sudo ldconfig

# Or set LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

### Compilation Errors

If compilation fails with HTTP/3 errors:

1. Verify ngtcp2 and nghttp3 are installed:
   ```bash
   ls -la /usr/local/lib/libngtcp2*
   ls -la /usr/local/lib/libnghttp3*
   ```

2. Check pkg-config can find them:
   ```bash
   pkg-config --cflags ngtcp2
   pkg-config --libs ngtcp2
   ```

### Port Permission Issues

HTTP/3 uses UDP port 443, which requires root privileges:

```bash
# Option 1: Run with sudo
sudo php examples/http3_server.php

# Option 2: Use a higher port (>1024)
# Edit http3_server.php and change port to 8443
```

### Firewall Issues

Ensure UDP port 443 is open:

```bash
# For UFW
sudo ufw allow 443/udp

# For iptables
sudo iptables -A INPUT -p udp --dport 443 -j ACCEPT
```

## Performance Tuning

### System Settings

Increase UDP buffer sizes for better performance:

```bash
# Add to /etc/sysctl.conf
net.core.rmem_max = 2500000
net.core.wmem_max = 2500000

# Apply changes
sudo sysctl -p
```

### Server Configuration

Adjust HTTP/3 settings in your PHP code:

```php
$server->set([
    'http3_max_field_section_size' => 65536,  // Increase for large headers
    'http3_qpack_max_table_capacity' => 8192, // Increase for better compression
    'http3_qpack_blocked_streams' => 200,     // Increase for more concurrent streams
]);
```

## Additional Resources

- [Swoole Documentation](https://www.swoole.co.uk/)
- [ngtcp2 Documentation](https://nghttp2.org/ngtcp2/)
- [RFC 9000 - QUIC](https://www.rfc-editor.org/rfc/rfc9000.html)
- [RFC 9114 - HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)

## Quick Start Script

For convenience, here's a complete build script:

```bash
#!/bin/bash
set -e

# Install system dependencies
sudo apt-get update
sudo apt-get install -y build-essential autoconf libtool pkg-config libssl-dev php-dev php-cli

# Build ngtcp2
cd /tmp
git clone --depth 1 --branch v1.16.0 https://github.com/ngtcp2/ngtcp2.git
cd ngtcp2
autoreconf -i
CFLAGS="-O2 -g0" ./configure --prefix=/usr/local --with-openssl --enable-lib-only
make -j$(nproc)
sudo make install

# Build sfparse (nghttp3 dependency)
cd /tmp
git clone --depth 1 https://github.com/ngtcp2/sfparse.git
cd sfparse
autoreconf -i
CFLAGS="-O2 -g0" ./configure --prefix=/usr/local
make -j$(nproc)
sudo make install
sudo mkdir -p /usr/local/include/sfparse
sudo cp -f sfparse.h /usr/local/include/sfparse/

# Build nghttp3
cd /tmp
git clone --depth 1 --branch v1.12.0 https://github.com/ngtcp2/nghttp3.git
cd nghttp3
autoreconf -i
sudo ldconfig
PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH \
CFLAGS="-O2 -g0" \
CPPFLAGS="-I/usr/local/include" \
LDFLAGS="-L/usr/local/lib" \
./configure --prefix=/usr/local --enable-lib-only
make -j$(nproc)
sudo make install

# Update library cache
sudo ldconfig

# Build Swoole
cd /home/user/swoole-src
phpize
./configure --enable-swoole --enable-openssl --enable-http2 \
    --with-ngtcp2-dir=/usr/local --with-nghttp3-dir=/usr/local
make -j$(nproc)
sudo make install

# Enable extension
echo "extension=swoole.so" | sudo tee /etc/php/$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')/cli/conf.d/20-swoole.ini

# Verify
php -r 'var_dump(defined("SWOOLE_USE_HTTP3") && SWOOLE_USE_HTTP3);'

echo "HTTP/3 support enabled!"
```

Save this as `build_http3.sh`, make it executable with `chmod +x build_http3.sh`, and run it.
