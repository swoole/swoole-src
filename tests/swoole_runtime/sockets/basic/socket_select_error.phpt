--TEST--
swoole_runtime/sockets/basic: socket_select() error conditions
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
<?php
if (!extension_loaded('sockets')) die('skip socket extension not available');
die('skip unsupport');
?>
--FILE--
<?php
use Swoole\Runtime;
use function Swoole\Coroutine\run;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {

$r = $w = $e = ['no resource'];
try {
    socket_select($r, $w, $e, 1);
} catch (TypeError $ex) {
    echo $ex->getMessage(), PHP_EOL;
}
});
?>
--EXPECT--
socket_select(): Argument #1 ($read) must only have elements of type Socket, string given
