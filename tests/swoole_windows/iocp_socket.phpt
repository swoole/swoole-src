--TEST--
swoole_windows: iocp socket
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (stripos(PHP_OS, 'WIN') !== 0) {
    die('skip Windows only');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use function Swoole\Coroutine\run;

run(function (): void {
    $server = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    try {
        if (!Assert::true($server->bind('127.0.0.1', 0))) {
            return;
        }
        if (!Assert::true($server->listen())) {
            return;
        }

        $address = $server->getsockname();
        if (!Assert::isArray($address)) {
            return;
        }
        if (!Assert::greaterThan($address['port'], 0)) {
            return;
        }
        $port = $address['port'];

        $completed = new Swoole\Coroutine\Channel(1);
        go(function () use ($server, $completed): void {
            try {
                $connection = $server->accept(5);
                if (!Assert::assert($connection !== false, 'failed to accept socket')) {
                    return;
                }
                try {
                    if (!Assert::same($connection->recvAll(4, 5), 'ping')) {
                        return;
                    }
                    Assert::same($connection->sendAll('pong', 5), 4);
                } finally {
                    $connection->close();
                }
            } finally {
                $completed->push(true);
            }
        });

        $client = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        try {
            if (!Assert::true($client->connect('127.0.0.1', $port, 5))) {
                return;
            }
            if (!Assert::same($client->sendAll('ping', 5), 4)) {
                return;
            }
            Assert::same($client->recvAll(4, 5), 'pong');
        } finally {
            $client->close();

            $acceptCompleted = $completed->pop(6);
            Assert::same($acceptCompleted, true);
        }
    } finally {
        $server->close();
    }
});

echo "DONE\n";
?>
--EXPECT--
DONE
