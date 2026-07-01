--TEST--
swoole_http_client_coro: invalid port
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

foreach ([-1, 65536] as $port) {
    try {
        new Swoole\Coroutine\Http\Client('127.0.0.1', $port);
    } catch (Swoole\Coroutine\Http\Client\Exception $e) {
        echo $e->getMessage() . "\n";
    }
}

new Swoole\Coroutine\Http\Client('unix:/' . UNIXSOCK_PATH, 0);
echo "DONE\n";
?>
--EXPECT--
The port is invalid
The port is invalid
DONE
