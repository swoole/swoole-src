--TEST--
swoole_socket_coro: setOption SO_RCVTIMEO
--DESCRIPTION--
-wrong params
-set/get params comparison
--SKIPIF--
--FILE--
<?php
$socket = new Co\Socket(AF_INET, SOCK_STREAM, SOL_TCP);
$socket->bind("127.0.0.1", 9501);

assert($socket->setOption(SOL_SOCKET, SO_REUSEADDR, true));
assert($socket->setOption(SOL_SOCKET, SO_REUSEPORT, true));

?>
--EXPECTF--

