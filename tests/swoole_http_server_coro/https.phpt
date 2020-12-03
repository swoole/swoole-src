--TEST--
swoole_http_server_coro: https
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$port = get_one_free_port();

go(function () use ($port) {
    $server = new Co\Http\Server("127.0.0.1", $port, true);
    $server->set(['open_tcp_nodelay' => true,
        'ssl_cert_file' => SSL_FILE_DIR.'/server.crt',
        'ssl_key_file' => SSL_FILE_DIR.'/server.key',
    ]);
    $server->handle('/', function ($request, $response) {
        $response->end("<h1>Index</h1>");
    });
    $server->handle('/stop', function ($request, $response) use ($server) {
        $response->end("<h1>Stop</h1>");
        $server->shutdown();
    });
    $server->start();
});

go(function () use ($port) {
    echo httpGetBody("https://127.0.0.1:{$port}/") . PHP_EOL;
    echo httpGetBody("https://127.0.0.1:{$port}/stop?hello=1") . PHP_EOL;
});
swoole_event_wait();

?>
--EXPECT--
<h1>Index</h1>
<h1>Stop</h1>
