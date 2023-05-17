--TEST--
swoole_runtime: bug 4657
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Socket as BaseSocket;
use function Swoole\Coroutine\run;

$socket = socket_create(AF_INET, SOCK_STREAM, 0);
Assert::eq(get_class($socket), Socket::class);

run(function () {
    $socket = socket_create(AF_INET, SOCK_STREAM, 0);
    Assert::eq(get_class($socket), Swoole\Coroutine\Socket::class);
    Assert::true($socket instanceof BaseSocket);
});

$socket = socket_create(AF_INET, SOCK_STREAM, 0);
Assert::eq(get_class($socket), Socket::class);
?>
--EXPECTF--
