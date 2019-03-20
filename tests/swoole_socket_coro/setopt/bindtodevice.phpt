--TEST--
swoole_socket_coro: setOption option:SO_BINDTODEVICE
--SKIPIF--
<?php
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
$socket = new Co\Socket(AF_INET, SOCK_STREAM, SOL_TCP);

$retval_1 = $socket->setOption(SOL_SOCKET, SO_BINDTODEVICE, "lo");
var_dump($retval_1);

$retval_2 =  $socket->setOption(SOL_SOCKET, SO_BINDTODEVICE, "ethIDONOTEXIST");
var_dump($retval_2);
?>
--EXPECTF--
bool(true)

Warning: Swoole\Coroutine\Socket::setOption(): setsockopt(4) failed. Error: No such device[%d]. in %s on line %d
bool(false)
--CREDITS--
Damjan Cvetko, foreach.org
