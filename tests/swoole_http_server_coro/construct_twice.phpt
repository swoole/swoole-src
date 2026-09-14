--TEST--
swoole_http_server_coro: construct twice
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http\Server;

$server = new Server('127.0.0.1', 0);

try {
    $server->__construct('0.0.0.0', 0);
} catch (Error $e) {
    echo $e->getMessage() . PHP_EOL;
}

Assert::same($server->host, '127.0.0.1');
?>
--EXPECT--
Constructor of Swoole\Coroutine\Http\Server can only be called once
