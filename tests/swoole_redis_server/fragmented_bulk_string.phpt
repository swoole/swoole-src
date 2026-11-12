--TEST--
swoole_redis_server: bulk string split across packets must not be accepted early
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Client;
use Swoole\Redis\Server;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $client = new Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    Assert::true($client->connect('127.0.0.1', $pm->getFreePort()));
    $client->send("*2\r\n$3\r\nSET\r\n");
    usleep(100000);
    $client->send("$10\r\n12\r\n");
    usleep(100000);
    $client->send("45\r\n");
    usleep(100000);
    $client->send("67\r\n");
    Assert::same($client->recv(), "+OK\r\n");
    $client->send("*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n");
    Assert::same($client->recv(), "$5\r\nvalue\r\n");
    $client->close();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->setHandler('SET', function ($fd, $data) use ($server) {
        $server->send($fd, Server::format(Server::STATUS, $data[0] === "12\r\n45\r\n67" ? 'OK' : 'BAD'));
    });
    $server->setHandler('GET', function ($fd) use ($server) {
        $server->send($fd, Server::format(Server::STRING, 'value'));
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
