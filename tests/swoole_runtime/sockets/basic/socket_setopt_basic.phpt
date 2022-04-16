--TEST--
swoole_runtime/sockets/basic: Test socket_setopt() basic functionality
--CREDITS--
Rodrigo Prado de Jesus <royopa [at] gmail [dot] com>
User Group: PHPSP #PHPTestFestBrasil
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
<?php
if (!extension_loaded('sockets')) {
    die('skip. Sockets extension is not available.');
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
socket_set_block($socket);

//set/get comparison
$options = array("sec" => 1, "usec" => 0);
$retval_1 = socket_setopt( $socket, SOL_SOCKET, SO_SNDTIMEO, $options);
$retval_2 = socket_getopt( $socket, SOL_SOCKET, SO_SNDTIMEO);

var_dump($retval_1);
var_dump($retval_2 === $options);
socket_close($socket);
});
?>
--EXPECT--
bool(true)
bool(true)
