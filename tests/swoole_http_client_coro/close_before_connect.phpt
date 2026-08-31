--TEST--
swoole_http_client_coro: close before connect
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$client = new Swoole\Coroutine\Http\Client('127.0.0.1', 9501);
Assert::false($client->close());
?>
--EXPECT--
