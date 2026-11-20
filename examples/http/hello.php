<?php
// A minimal HTTP server. Run it, then curl http://127.0.0.1:9501/ in another
// terminal. It keeps running until you press Ctrl+C.
// Run: php examples/http/hello.php
$server = new Swoole\Http\Server('127.0.0.1', 9501);
$server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
    $response->header('Content-Type', 'text/plain');
    $response->end('Hello, Swoole!' . PHP_EOL);
});
$server->start();
