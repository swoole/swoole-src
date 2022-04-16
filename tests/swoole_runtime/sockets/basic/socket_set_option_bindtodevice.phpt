--TEST--
swoole_runtime/sockets/basic:SO_BINDTODEVICE
--DESCRIPTION--
-Bind to loopback 'lo' device (should exist)
-Bind to unexisting device
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
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
use Swoole\Runtime;
use function Swoole\Coroutine\run;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {

$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);

if (!$socket) {
        die('Unable to create AF_INET socket [socket]');
}
// wrong params
$retval_1 = socket_set_option( $socket, SOL_SOCKET, SO_BINDTODEVICE, "lo");
var_dump($retval_1);
$retval_2 = socket_set_option( $socket, SOL_SOCKET, SO_BINDTODEVICE, "ethIDONOTEXIST");
var_dump($retval_2);

socket_close($socket);
});
?>
--EXPECTF--
bool(true)

Warning: Swoole\Coroutine\Socket::setOption(): setsockopt(%d) failed, Error: No such device[%d] in %s on line %d
bool(false)
--CREDITS--
Damjan Cvetko, foreach.org
