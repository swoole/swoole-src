--TEST--
swoole_client_coro: exportSocket returns false before connect
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
use Swoole\Coroutine\Client;
use function Swoole\Coroutine\run;

run(function () {
    $client = new Client(SWOOLE_SOCK_TCP);
    var_dump($client->exportSocket());
});
?>
--EXPECT--
bool(false)
