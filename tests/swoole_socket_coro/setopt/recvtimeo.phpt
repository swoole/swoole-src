--TEST--
swoole_socket_coro/setopt: setOption SO_RCVTIMEO
--DESCRIPTION--
-wrong params
-set/get params comparison
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$socket = new Co\Socket(AF_INET, SOCK_STREAM, SOL_TCP);

//wrong params
$retval_1 = $socket->setOption(SOL_SOCKET, SO_RCVTIMEO, array());
Assert::assert($retval_1 === false);
$options = array("sec" => 1, "usec" => 0);
$retval_2 = $socket->setOption(SOL_SOCKET, SO_RCVTIMEO, $options);
Assert::assert($retval_2 === true);

?>
--EXPECTF--
Warning: Swoole\Coroutine\Socket::setOption(): no key "sec" passed in optval in %s on line %d
