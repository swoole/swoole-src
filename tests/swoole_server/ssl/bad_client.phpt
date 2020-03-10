--TEST--
swoole_server/ssl: bad client
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

define('ERROR_FILE', __DIR__.'/ssl_error');

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    $port = $pm->getFreePort();
    $client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC); //同步阻塞
    if (!$client->connect('127.0.0.1', $port))
    {
        exit("connect failed\n");
    }
    $client->send("hello world");
    Assert::same($client->recv(), "");
    echo httpGetBody("https://127.0.0.1:{$port}/stop?hello=1") . PHP_EOL;
};

$pm->childFunc = function () use ($pm) {
    go(function () use ($pm) {
        $server = new Co\Http\Server("127.0.0.1", $pm->getFreePort(), true);
        $server->set(
            [
                'open_tcp_nodelay' => true,
                'ssl_cert_file' => dirname(__DIR__) . '/include/api/swoole_http_server/localhost-ssl/server.crt',
                'ssl_key_file' => dirname(__DIR__) . '/include/api/swoole_http_server/localhost-ssl/server.key',
            ]
        );
        $server->handle('/', function ($request, $response) {
            $response->end("<h1>Index</h1>");
        });
        $server->handle('/stop', function ($request, $response) use ($server) {
            $response->end("<h1>Stop</h1>");
            $server->shutdown();
        });
        $server->start();
    });
    Swoole\Event::wait();
};

$pm->childFirst();
$pm->run();
readfile(ERROR_FILE);
unlink(ERROR_FILE);
?>
--EXPECTF--
[%s]	WARNING	swSSL_accept: bad SSL client[127.0.0.1:%d], reason=%d, error_string=error:%s
