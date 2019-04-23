--TEST--
swoole_socket_coro/setopt:SO_BINDTODEVICE
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
if (!extension_loaded('sockets')) {
    die('SKIP sockets extension not available.');
}
if (!defined("SO_BINDTODEVICE")) {
    die('SKIP SO_BINDTODEVICE not supported on this platform.');
}
if (!function_exists("posix_getuid") || posix_getuid() != 0) {
    die('SKIP SO_BINDTODEVICE requires root permissions.');
}
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$socket = new Co\Socket(AF_INET, SOCK_STREAM, SOL_TCP);

$retval_1 = $socket->setOption(SOL_SOCKET, SO_BINDTODEVICE, "lo");
Assert::assert($retval_1 === true);

$retval_2 = $socket->setOption(SOL_SOCKET, SO_BINDTODEVICE, "ethIDONOTEXIST");
Assert::assert($retval_2 === false);
?>
--EXPECTF--
Warning: Swoole\Coroutine\Socket::setOption(): setsockopt(%d) failed, Error: No such device[%d] in %s on line %d
