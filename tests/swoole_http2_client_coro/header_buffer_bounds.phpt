--TEST--
swoole_http2_client_coro: reject header blocks larger than the peer frame limit
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

$pm->parentFunc = function () use ($pm) {
    Swoole\Coroutine\run(function () use ($pm) {
        $client = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
        Assert::true($client->connect());

        $request = new Swoole\Http2\Request;
        $request->cookies = ['large' => str_repeat('0', 100000)];

        Assert::false($client->send($request));
        // NGHTTP2_ERR_FRAME_SIZE_ERROR
        Assert::same($client->errCode, -522);
        Assert::contains($client->errMsg, 'exceeds peer max frame size 16384');
        Assert::false($client->connected);
    });

    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    Swoole\Coroutine\run(function () use ($pm) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), false);
        $server->handle(function (Connection $connection) use ($server) {
            $connection->send(http2_frame(SWOOLE_HTTP2_TYPE_SETTINGS, 0, 0));
            while (($data = $connection->recv()) !== '' && $data !== false) {
            }
            $connection->close();
            $server->shutdown();
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
