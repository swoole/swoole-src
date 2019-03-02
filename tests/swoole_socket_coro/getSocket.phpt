--TEST--
swoole_socket_coro: getSocket
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
go(function () {
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
    var_dump($socket->getSocket());
    Assert::eq($socket->getSocket(), $socket->getSocket());
});
?>
--EXPECTF--
resource(%d) of type (Socket)
