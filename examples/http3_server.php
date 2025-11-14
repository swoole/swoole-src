<?php
/**
 * Simple HTTP/3 Server Example
 *
 * This example demonstrates how to create a basic HTTP/3 server using Swoole.
 * The server listens on port 443 and responds with "hello from http3 server!"
 */

// Check if HTTP/3 support is available
if (!defined('SWOOLE_USE_HTTP3') || !SWOOLE_USE_HTTP3) {
    die("Error: Swoole was not compiled with HTTP/3 support.\n" .
        "Please recompile Swoole with --with-ngtcp2-dir and --with-nghttp3-dir options.\n");
}

// Create HTTP/3 server
$server = new Swoole\Http3\Server("0.0.0.0", 443);

// Configure server settings
$server->set([
    // SSL certificate and key (required for HTTP/3)
    'ssl_cert_file' => __DIR__ . '/ssl/cert.pem',
    'ssl_key_file'  => __DIR__ . '/ssl/key.pem',

    // HTTP/3 specific settings
    'http3_max_field_section_size' => 65536,  // Maximum header size
    'http3_qpack_max_table_capacity' => 4096, // QPACK dynamic table size
    'http3_qpack_blocked_streams' => 100,     // Max blocked streams
]);

// Handle HTTP/3 requests
$server->on('request', function (Swoole\Http3\Request $request, Swoole\Http3\Response $response) {
    // Log request information
    echo "Received HTTP/3 request:\n";
    echo "  Method: " . $request->server['request_method'] . "\n";
    echo "  URI: " . $request->server['request_uri'] . "\n";
    echo "  Protocol: " . $request->server['server_protocol'] . "\n";
    echo "  Stream ID: " . $request->streamId . "\n";

    // Set response headers
    $response->header('Content-Type', 'text/plain; charset=utf-8');
    $response->header('X-Powered-By', 'Swoole HTTP/3');

    // Set HTTP status code
    $response->status(200);

    // Send response body
    $response->end("hello from http3 server!\n");

    echo "  Response sent\n\n";
});

echo "HTTP/3 Server starting...\n";
echo "Listening on: https://0.0.0.0:443 (HTTP/3)\n";
echo "Press Ctrl+C to stop\n\n";

// Start the server
$server->start();
