--TEST--
swoole_pdo_pgsql: cancel connect
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php

require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\CanceledException;

// The server accepts the TCP connection but never answers the startup packet.
$server = stream_socket_server('tcp://127.0.0.1:0');
$port = (int) explode(':', stream_socket_get_name($server, false))[1];

Co\run(static function () use ($port): void {
    $cid = Co\go(static function () use ($port): void {
        try {
            new PDO("pgsql:host=127.0.0.1;port={$port};dbname=test", 'user', 'pass');
        } catch (CanceledException $e) {
            echo "canceled\n";
        }
    });
    Assert::true(Coroutine::cancel($cid, true));
});
?>
--EXPECT--
canceled
