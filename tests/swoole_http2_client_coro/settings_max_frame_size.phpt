--TEST--
swoole_http2_client_coro: reject invalid peer maximum frame sizes
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Server;
use Swoole\Coroutine\Server\Connection;

function http2_frame(int $type, int $flags, int $streamId, string $payload = ''): string
{
    return substr(pack('N', strlen($payload)), 1)
        . chr($type)
        . chr($flags)
        . pack('N', $streamId & 0x7fffffff)
        . $payload;
}

$pm = new ProcessManager;
$invalidValues = [0, 16777216];

$pm->parentFunc = function () use ($pm, $invalidValues) {
    Swoole\Coroutine\run(function () use ($pm, $invalidValues) {
        foreach ($invalidValues as $value) {
            $client = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
            Assert::true($client->connect());
            Assert::false($client->recv(0.1));
            Assert::false($client->connected);
            Assert::same($client->errCode, SWOOLE_HTTP2_ERROR_PROTOCOL_ERROR);
            Assert::contains($client->errMsg, (string) $value);
        }
    });

    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm, $invalidValues) {
    Swoole\Coroutine\run(function () use ($pm, $invalidValues) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), false);
        $nextValue = 0;
        $completed = 0;
        $server->handle(function (Connection $connection) use ($server, $invalidValues, &$nextValue, &$completed) {
            $value = $invalidValues[$nextValue++];
            $settings = http2_frame(SWOOLE_HTTP2_TYPE_SETTINGS, 0, 0, pack('nN', 5, $value));
            Assert::same($connection->send($settings), strlen($settings));
            $connection->recv(0.5);
            Swoole\Coroutine::sleep(0.2);
            $connection->close();
            if (++$completed === count($invalidValues)) {
                $server->shutdown();
            }
        });

        $pm->wakeup();
        $server->start();
    });
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
