--TEST--
swoole_socket_coro: getsockname
--SKIPIF--
<?php require __DIR__.'/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__.'/../include/bootstrap.php';

$conn = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
$conn->bind('127.0.0.1');
$info = $conn->getsockname();
Assert::eq($info and $info['address'], '127.0.0.1' and $info['port'] > 0);
?>
--EXPECT--
