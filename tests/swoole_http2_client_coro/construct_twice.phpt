--TEST--
swoole_http2_client_coro: construct twice
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http2\Client;

$client = new Client('127.0.0.1', 80);

try {
    $client->__construct('localhost', 80);
} catch (Error $e) {
    echo $e->getMessage() . PHP_EOL;
}
?>
--EXPECT--
Constructor of Swoole\Coroutine\Http2\Client can only be called once
