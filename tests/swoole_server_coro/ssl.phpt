--TEST--
swoole_server_coro: ssl
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Server;
use Swoole\Coroutine\Server\Connection;

$pm = new ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    $client = new swoole_client(SWOOLE_SOCK_TCP | SWOOLE_SSL, SWOOLE_SOCK_SYNC); //同步阻塞
    if (!$client->connect('127.0.0.1', $pm->getFreePort()))
    {
        exit("connect failed\n");
    }
    $client->send("hello world");
    Assert::same($client->recv(), "Swoole hello world");
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    go(function () use ($pm) {
        $server = new Server('0.0.0.0', $pm->getFreePort(), true);
        $server->set([
            'log_file' => '/dev/null',
            'ssl_cert_file' => SSL_FILE_DIR.'/server.crt',
            'ssl_key_file' => SSL_FILE_DIR.'/server.key',
        ]);
        $server->handle(function (Connection $conn) use ($server) {
            $data = $conn->recv();
            $conn->send("Swoole $data");
            $server->shutdown();
        });
        $pm->wakeup();
        $server->start();
    });
    swoole_event::wait();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
