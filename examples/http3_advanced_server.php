<?php
/**
 * Advanced HTTP/3 Server Example
 *
 * This example demonstrates advanced features of Swoole HTTP/3 server:
 * - Request routing
 * - Header manipulation
 * - Query parameters and cookies
 * - JSON responses
 * - Static file serving
 * - Request logging
 */

// Check if HTTP/3 support is available
if (!defined('SWOOLE_USE_HTTP3') || !SWOOLE_USE_HTTP3) {
    die("Error: Swoole was not compiled with HTTP/3 support.\n");
}

// Create HTTP/3 server
$server = new Swoole\Http3\Server("0.0.0.0", 8443);

// Configure server settings
$server->set([
    'ssl_cert_file' => __DIR__ . '/ssl/cert.pem',
    'ssl_key_file'  => __DIR__ . '/ssl/key.pem',
    'http3_max_field_section_size' => 65536,
    'http3_qpack_max_table_capacity' => 4096,
    'http3_qpack_blocked_streams' => 100,
]);

// Statistics
$stats = [
    'requests' => 0,
    'start_time' => time(),
];

// Request handler with routing
$server->on('request', function (Swoole\Http3\Request $request, Swoole\Http3\Response $response) use (&$stats) {
    $stats['requests']++;

    // Log request
    $timestamp = date('Y-m-d H:i:s');
    $method = $request->server['request_method'];
    $uri = $request->server['request_uri'];
    $protocol = $request->server['server_protocol'];
    $streamId = $request->streamId;

    echo "[{$timestamp}] {$method} {$uri} ({$protocol}) [Stream: {$streamId}]\n";

    // Set common headers
    $response->header('Server', 'Swoole-HTTP3');
    $response->header('X-Powered-By', 'Swoole/' . SWOOLE_VERSION);
    $response->header('X-Stream-ID', (string)$streamId);

    // Simple routing
    $path = parse_url($uri, PHP_URL_PATH);

    switch ($path) {
        case '/':
        case '/hello':
            // Simple hello response
            $response->header('Content-Type', 'text/plain; charset=utf-8');
            $response->status(200);
            $response->end("hello from http3 server!\n");
            break;

        case '/json':
            // JSON response
            $data = [
                'message' => 'Hello from HTTP/3!',
                'protocol' => 'HTTP/3',
                'stream_id' => $streamId,
                'timestamp' => time(),
                'server' => 'Swoole',
            ];

            $response->header('Content-Type', 'application/json; charset=utf-8');
            $response->status(200);
            $response->end(json_encode($data, JSON_PRETTY_PRINT) . "\n");
            break;

        case '/headers':
            // Display request headers
            $output = "Request Headers:\n";
            $output .= "================\n\n";

            foreach ($request->header as $key => $value) {
                $output .= "{$key}: {$value}\n";
            }

            $response->header('Content-Type', 'text/plain; charset=utf-8');
            $response->status(200);
            $response->end($output);
            break;

        case '/query':
            // Display query parameters
            $output = "Query Parameters:\n";
            $output .= "=================\n\n";

            if (!empty($request->get)) {
                foreach ($request->get as $key => $value) {
                    $output .= "{$key} = {$value}\n";
                }
            } else {
                $output .= "No query parameters\n";
            }

            $output .= "\nExample: /query?name=John&age=30\n";

            $response->header('Content-Type', 'text/plain; charset=utf-8');
            $response->status(200);
            $response->end($output);
            break;

        case '/cookie':
            // Set and display cookies
            $response->header('Set-Cookie', 'test_cookie=hello_http3; Path=/; Secure; HttpOnly');
            $response->header('Set-Cookie', 'session_id=' . uniqid() . '; Path=/; Secure; HttpOnly');

            $output = "Cookies Set!\n";
            $output .= "============\n\n";
            $output .= "test_cookie = hello_http3\n";
            $output .= "session_id = " . uniqid() . "\n\n";

            if (!empty($request->cookie)) {
                $output .= "Existing Cookies:\n";
                foreach ($request->cookie as $key => $value) {
                    $output .= "  {$key} = {$value}\n";
                }
            }

            $response->header('Content-Type', 'text/plain; charset=utf-8');
            $response->status(200);
            $response->end($output);
            break;

        case '/stats':
            // Server statistics
            $uptime = time() - $stats['start_time'];
            $hours = floor($uptime / 3600);
            $minutes = floor(($uptime % 3600) / 60);
            $seconds = $uptime % 60;

            $data = [
                'server' => [
                    'protocol' => 'HTTP/3',
                    'version' => SWOOLE_VERSION,
                    'uptime' => sprintf('%02d:%02d:%02d', $hours, $minutes, $seconds),
                    'uptime_seconds' => $uptime,
                ],
                'statistics' => [
                    'total_requests' => $stats['requests'],
                    'requests_per_second' => $uptime > 0 ? round($stats['requests'] / $uptime, 2) : 0,
                ],
            ];

            $response->header('Content-Type', 'application/json; charset=utf-8');
            $response->status(200);
            $response->end(json_encode($data, JSON_PRETTY_PRINT) . "\n");
            break;

        case '/info':
            // Server information
            $output = "HTTP/3 Server Information\n";
            $output .= "=========================\n\n";
            $output .= "Protocol: {$protocol}\n";
            $output .= "Method: {$method}\n";
            $output .= "URI: {$uri}\n";
            $output .= "Stream ID: {$streamId}\n";
            $output .= "Swoole Version: " . SWOOLE_VERSION . "\n";
            $output .= "HTTP/3 Enabled: " . (SWOOLE_USE_HTTP3 ? 'Yes' : 'No') . "\n";

            $response->header('Content-Type', 'text/plain; charset=utf-8');
            $response->status(200);
            $response->end($output);
            break;

        case '/large':
            // Test with large response
            $size = isset($request->get['size']) ? (int)$request->get['size'] : 1024;
            $size = min($size, 1024 * 1024); // Max 1MB

            $data = str_repeat('A', $size);

            $response->header('Content-Type', 'text/plain');
            $response->header('Content-Length', (string)strlen($data));
            $response->status(200);
            $response->end($data);
            break;

        case '/stream':
            // Streaming response (chunked)
            $response->header('Content-Type', 'text/plain; charset=utf-8');
            $response->status(200);

            $response->write("Starting stream...\n");
            $response->write("Chunk 1\n");
            $response->write("Chunk 2\n");
            $response->write("Chunk 3\n");
            $response->end("Stream complete!\n");
            break;

        default:
            // 404 Not Found
            $response->header('Content-Type', 'text/plain; charset=utf-8');
            $response->status(404);
            $response->end("404 Not Found\n\nAvailable endpoints:\n" .
                "  /           - Hello message\n" .
                "  /json       - JSON response\n" .
                "  /headers    - Display request headers\n" .
                "  /query      - Display query parameters\n" .
                "  /cookie     - Set and display cookies\n" .
                "  /stats      - Server statistics\n" .
                "  /info       - Server information\n" .
                "  /large      - Large response (add ?size=N)\n" .
                "  /stream     - Streaming response\n");
            break;
    }
});

echo "╔════════════════════════════════════════════════╗\n";
echo "║      Swoole HTTP/3 Advanced Server             ║\n";
echo "╚════════════════════════════════════════════════╝\n";
echo "\n";
echo "Server: https://0.0.0.0:8443 (HTTP/3)\n";
echo "Swoole Version: " . SWOOLE_VERSION . "\n";
echo "HTTP/3 Support: " . (SWOOLE_USE_HTTP3 ? 'Enabled' : 'Disabled') . "\n";
echo "\n";
echo "Available endpoints:\n";
echo "  /           - Hello message\n";
echo "  /json       - JSON response\n";
echo "  /headers    - Display request headers\n";
echo "  /query      - Display query parameters\n";
echo "  /cookie     - Set and display cookies\n";
echo "  /stats      - Server statistics\n";
echo "  /info       - Server information\n";
echo "  /large      - Large response (add ?size=N)\n";
echo "  /stream     - Streaming response\n";
echo "\n";
echo "Press Ctrl+C to stop\n";
echo "\n";
echo "Request Log:\n";
echo "============\n";

// Start the server
$server->start();
