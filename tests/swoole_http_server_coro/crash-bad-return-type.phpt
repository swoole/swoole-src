--TEST--
swoole_http_server_coro: crash - bad return type
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$port = get_one_free_port();

Co::set(['log_file' => '/dev/null']);

go(function () use ($port) {
    $server = new Co\Http\Server("127.0.0.1", $port, true);
    $server->set([
        'open_tcp_nodelay' => true,
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
    try {
        echo httpGetBody("http://127.0.0.1:{$port}/") . PHP_EOL;
    } catch (Throwable $e) {
        Assert::contains($e->getMessage(), 'Connection reset by peer');
        echo "Bad Client\n";
    }
    echo httpGetBody("https://127.0.0.1:{$port}/") . PHP_EOL;
    echo httpGetBody("https://127.0.0.1:{$port}/stop?hello=1") . PHP_EOL;
});
Swoole\Event::wait();

?>
--EXPECT--
Bad Client
<h1>Index</h1>
<h1>Stop</h1>
