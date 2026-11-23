--TEST--
swoole_redis_server: malformed bulk string lengths close the connection
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Client;
use Swoole\Redis\Server;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $payloads = [
        "*1\r\n\$-2\r\n\r\n",
        "*1\r\n\$4\r\nPING\r\n\$x\r\n",
    ];
    foreach ($payloads as $payload) {
        $client = new Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort()));
        $client->send($payload);
        Assert::same($client->recv(), '');
        $client->close();
    }

    // The server survives and still answers.
    $client = new Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    Assert::true($client->connect('127.0.0.1', $pm->getFreePort()));
    $client->send("*2\r\n\$4\r\nECHO\r\n\$2\r\nhi\r\n");
    Assert::same($client->recv(), "\$2\r\nhi\r\n");
    $client->close();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->setHandler('ECHO', function ($fd, $data) use ($server) {
        $server->send($fd, Server::format(Server::STRING, $data[0] ?? ''));
    });
    $server->setHandler('PING', function ($fd) use ($server) {
        $server->send($fd, Server::format(Server::STATUS, 'PONG'));
    });
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
echo "SUCCESS\n";
?>
--EXPECT--
SUCCESS
