<?php
// Coroutine\Http\Server runs inside a coroutine, with no master/manager
// processes. Run it, then curl http://127.0.0.1:9510/ (Ctrl+C to stop).
// Run: php examples/coroutine/http_server_hello.php
use Swoole\Coroutine\Http\Server;
use function Swoole\Coroutine\run;

run(function () {
    $server = new Server('127.0.0.1', 9510, false, true);
    $server->handle('/', function ($request, $response) {
        $response->end('Hello from a coroutine HTTP server');
    });
    $server->start();
});
