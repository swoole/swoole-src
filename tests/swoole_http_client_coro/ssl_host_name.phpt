--TEST--
swoole_http_client_coro: https client with ssl_host_name
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $c = new Co\Http\Client('127.0.0.1', $pm->getFreePort(), true);
        $c->set([
            'timeout' => 5,
            'ssl_host_name' => '127.0.0.1'
        ]);
        $c->get('/');
        Assert::assert(strlen($c->body) > 0);
        Assert::same($c->statusCode, 200);
    });
    Swoole\Event::wait();
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $server->set([
        'log_file' => '/dev/null',
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
    ]);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function ($request, $response) {
        $response->end('OK');
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
