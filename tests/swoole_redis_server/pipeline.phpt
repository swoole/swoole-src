--TEST--
swoole_redis_server: pipelined requests in one packet
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Client;
use Swoole\Redis\Server;

Assert::setThrowException(true);
foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $pm = new ProcessManager;
    $pm->parentFunc = function () use ($pm) {
        $client = new Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
        $client->set(['timeout' => 2]);
        $read = function (string $expected) use ($client): void {
            $data = '';
            while (strlen($data) < strlen($expected)) {
                $chunk = $client->recv();
                Assert::notEmpty($chunk);
                $data .= $chunk;
            }
            Assert::same($data, $expected);
        };
        try {
            Assert::true($client->connect('127.0.0.1', $pm->getFreePort()));
            $get = fn ($k) => "*2\r\n$3\r\nGET\r\n$" . strlen($k) . "\r\n$k\r\n";
            $ping = "*1\r\n$4\r\nPING\r\n";
            $prefix = $get('a') . $ping . $get('b') . substr($get('c'), 0, 13);
            Assert::same($client->send($prefix), strlen($prefix));
            // Complete commands must be answered while the final command is still incomplete.
            $read("$1\r\na\r\n+PONG\r\n$1\r\nb\r\n");
            $tail = substr($get('c'), 13);
            Assert::same($client->send($tail), strlen($tail));
            $read("$1\r\nc\r\n");

            Assert::same($client->send($ping . $ping), strlen($ping) * 2);
            $read("+PONG\r\n+PONG\r\n");
        } finally {
            $client->close();
            $pm->kill();
        }
    };

    $pm->childFunc = function () use ($pm, $mode) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set(['worker_num' => 1, 'log_file' => '/dev/null']);
        $server->setHandler('GET', function ($fd, $data) use ($server) {
            $server->send($fd, Server::format(Server::STRING, $data[0]));
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
}
echo "SUCCESS\n";
?>
--EXPECT--
SUCCESS
