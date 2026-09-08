--TEST--
swoole_runtime/ssl: cancel connect
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_no_ssl();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\CanceledException;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Server;
use Swoole\Coroutine\Server\Connection;
use Swoole\Runtime;

use function Swoole\Coroutine\go;
use function Swoole\Coroutine\run;

Runtime::enableCoroutine(SWOOLE_HOOK_TCP | SWOOLE_HOOK_TLS);

run(function () {
    $server = new Server('127.0.0.1');
    $connected = new Channel(1);
    $release = new Channel(1);

    go(function () use ($server, $connected, $release) {
        $server->handle(function (Connection $conn) use ($server, $connected, $release) {
            Assert::stringNotEmpty($conn->recv());
            $connected->push(true);
            $release->pop();
            $conn->close();
            $server->shutdown();
        });
        $server->start();
    });

    $canceled = false;
    $cid = go(function () use ($server, &$canceled) {
        $context = stream_context_create([
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
            ],
        ]);

        try {
            stream_socket_client(
                "tls://127.0.0.1:{$server->port}",
                $errno,
                $errstr,
                30,
                STREAM_CLIENT_CONNECT,
                $context
            );
        } catch (CanceledException $e) {
            $canceled = true;
        }
    });

    $connected->pop();
    Assert::true(Coroutine::cancel($cid, true));

    try {
        Assert::false(Coroutine::exists($cid));
        Assert::true($canceled);
    } finally {
        $release->push(true);
    }
});

echo "DONE\n";
?>
--EXPECTF--
Warning: stream_socket_client(): Unable to connect to tls://127.0.0.1:%d (Operation canceled) in %s on line %d
DONE
