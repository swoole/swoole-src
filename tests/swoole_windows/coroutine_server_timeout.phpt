--TEST--
swoole_windows: coroutine server retries accept timeouts
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (stripos(PHP_OS, 'WIN') !== 0) {
    die('skip Windows only');
}
if (!class_exists(Swoole\Coroutine\Server::class, false)) {
    die('skip coroutine server not available');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Server;
use Swoole\Coroutine\Server\Connection;
use Swoole\Coroutine\Socket;

use function Swoole\Coroutine\run;

class TimeoutServer extends Server
{
    public function setAcceptTimeout(): void
    {
        Assert::true($this->socket->setOption(SOL_SOCKET, SO_RCVTIMEO, ['sec' => 0, 'usec' => 10000]));
    }
}

run(function () {
    $server = new TimeoutServer('127.0.0.1');
    $server->setAcceptTimeout();
    $server->handle(function (Connection $connection) use ($server) {
        Assert::true(
            $connection->exportSocket()->setOption(SOL_SOCKET, SO_RCVTIMEO, ['sec' => 1, 'usec' => 0])
        );
        Assert::same('ping', $connection->recv());
        Assert::same(4, $connection->send('pong'));
        $connection->close();
        $server->shutdown();
    });

    Coroutine::create(function () use ($server) {
        Coroutine::sleep(0.05);
        $client = new Socket(AF_INET, SOCK_STREAM);
        Assert::true($client->connect('127.0.0.1', $server->port));
        Assert::same(4, $client->sendAll('ping'));
        Assert::same('pong', $client->recvAll(4));
        $client->close();
    });

    Assert::true($server->start());
});

echo "DONE\n";
?>
--EXPECT--
DONE
