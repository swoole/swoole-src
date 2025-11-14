# Swoole HTTP/3 Examples

This directory contains example scripts demonstrating HTTP/3 functionality in Swoole.

## Examples

### 1. Simple HTTP/3 Server (`http3_server.php`)

A minimal HTTP/3 server that responds with "hello from http3 server!" to all requests.

**Features:**
- Basic HTTP/3 server setup
- SSL/TLS configuration
- Simple request handling

**Usage:**
```bash
php http3_server.php
```

### 2. Advanced HTTP/3 Server (`http3_advanced_server.php`)

A feature-rich HTTP/3 server demonstrating various capabilities.

**Features:**
- Request routing
- JSON responses
- Header inspection
- Query parameter parsing
- Cookie handling
- Server statistics
- Streaming responses
- Large file handling

**Usage:**
```bash
php http3_advanced_server.php
```

**Endpoints:**
- `GET /` - Hello message
- `GET /json` - JSON response with server info
- `GET /headers` - Display all request headers
- `GET /query?key=value` - Display query parameters
- `GET /cookie` - Set and display cookies
- `GET /stats` - Server statistics (uptime, requests, etc.)
- `GET /info` - Server information
- `GET /large?size=1024` - Generate large response
- `GET /stream` - Streaming/chunked response

## Prerequisites

Before running these examples, ensure you have:

1. **Compiled Swoole with HTTP/3 support**
   ```bash
   # See HTTP3_BUILD_GUIDE.md for detailed instructions
   ./build_http3.sh
   ```

2. **Generated SSL certificates**
   ```bash
   ./generate_ssl_cert.sh
   ```

## Testing the Server

### Using curl

```bash
# Install curl with HTTP/3 support
# Recent versions of curl (7.66+) have HTTP/3 support

# Test basic endpoint
curl --http3 -k https://localhost:8443/

# Test JSON endpoint
curl --http3 -k https://localhost:8443/json

# Test with query parameters
curl --http3 -k "https://localhost:8443/query?name=John&age=30"

# Test headers
curl --http3 -k https://localhost:8443/headers -H "X-Custom-Header: test"

# Test with cookies
curl --http3 -k https://localhost:8443/cookie --cookie "existing=value"

# Get server statistics
curl --http3 -k https://localhost:8443/stats
```

### Using Chrome/Edge

1. Enable HTTP/3 in browser:
   - Chrome: `chrome://flags/#enable-quic`
   - Edge: `edge://flags/#enable-quic`

2. Navigate to `https://localhost:8443/`

3. Accept the self-signed certificate warning

4. Try different endpoints by changing the URL path

### Using Firefox

Firefox has built-in HTTP/3 support (enabled by default in recent versions):

1. Navigate to `https://localhost:8443/`
2. Accept the certificate warning
3. The browser will automatically use HTTP/3

## Verifying HTTP/3 Connection

### In Chrome DevTools

1. Open DevTools (F12)
2. Go to Network tab
3. Click on a request
4. Look at the "Protocol" column - it should show "h3" or "http/3"

### Using curl verbose mode

```bash
curl --http3 -k -v https://localhost:8443/
# Look for: "Using HTTP/3 Stream ID: X"
```

## Common Issues

### Port Permission Denied

If you get "Permission denied" on port 443:

**Solution 1:** Use a higher port (>1024) by editing the PHP file:
```php
$server = new Swoole\Http3\Server("0.0.0.0", 8443);
```

**Solution 2:** Run with sudo:
```bash
sudo php http3_server.php
```

### SSL Certificate Errors

The included certificate generation script creates self-signed certificates for testing only.

For production, use certificates from a trusted CA like:
- Let's Encrypt (free, automated)
- DigiCert
- Comodo

### HTTP/3 Not Available

If you get "HTTP/3 not available" errors:

1. Check Swoole was compiled with HTTP/3:
   ```bash
   php -r 'var_dump(SWOOLE_USE_HTTP3);'
   # Should output: bool(true)
   ```

2. Verify libraries are installed:
   ```bash
   ldconfig -p | grep ngtcp2
   ldconfig -p | grep nghttp3
   ```

3. Check firewall allows UDP traffic on the port:
   ```bash
   sudo ufw status
   sudo ufw allow 8443/udp
   ```

## Performance Testing

### Using h2load

```bash
# Install nghttp2-client for h2load
sudo apt-get install nghttp2-client

# Run benchmark (if h2load supports HTTP/3)
h2load -n 10000 -c 100 https://localhost:8443/
```

### Using Apache Bench with HTTP/3

Currently, standard Apache Bench (ab) doesn't support HTTP/3. Consider using:
- wrk with HTTP/3 support
- Custom benchmarking scripts
- Load testing tools like Locust

## Custom Examples

You can create your own HTTP/3 server by following this template:

```php
<?php

if (!SWOOLE_USE_HTTP3) {
    die("HTTP/3 not supported\n");
}

$server = new Swoole\Http3\Server("0.0.0.0", 8443);

$server->set([
    'ssl_cert_file' => __DIR__ . '/ssl/cert.pem',
    'ssl_key_file'  => __DIR__ . '/ssl/key.pem',
]);

$server->on('request', function ($request, $response) {
    $response->end("Your custom response");
});

$server->start();
```

## Additional Resources

- [Swoole Documentation](https://www.swoole.co.uk/)
- [HTTP/3 Specification (RFC 9114)](https://www.rfc-editor.org/rfc/rfc9114.html)
- [QUIC Specification (RFC 9000)](https://www.rfc-editor.org/rfc/rfc9000.html)
- [Main HTTP/3 Documentation](../README-HTTP3.md)
- [Build Guide](../HTTP3_BUILD_GUIDE.md)
