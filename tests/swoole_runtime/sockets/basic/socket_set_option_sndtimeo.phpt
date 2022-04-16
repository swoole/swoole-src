--TEST--
swoole_runtime/sockets/basic:SO_SNDTIMEO
--DESCRIPTION--
-wrong params
-set/get params comparison
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
<?php
if (!extension_loaded('sockets')) {
        die('SKIP sockets extension not available.');
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

//wrong params
try {
    $retval_1 = socket_set_option( $socket, SOL_SOCKET, SO_SNDTIMEO, []);
} catch (\ValueError $e) {
    echo $e->getMessage() . \PHP_EOL;
}

//set/get comparison
$options = array("sec" => 1, "usec" => 0);
$retval_2 = socket_set_option( $socket, SOL_SOCKET, SO_SNDTIMEO, $options);
$retval_3 = socket_get_option( $socket, SOL_SOCKET, SO_SNDTIMEO);

var_dump($retval_2);
var_dump($retval_3 === $options);
socket_close($socket);
});
?>
--EXPECTF--
Warning: Swoole\Coroutine\Socket::setOption(): no key "sec" passed in optval %s on line %d
bool(true)
bool(true)
