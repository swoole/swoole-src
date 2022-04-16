--TEST--
swoole_runtime/sockets/basic: Test parameter handling in socket_select().
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
<?php
if (!extension_loaded('sockets')) {
    die('SKIP The sockets extension is not loaded.');
}
die('skip unsupport');
?>
--FILE--
<?php
use Swoole\Runtime;
use function Swoole\Coroutine\run;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {

$sockets = null;
$write   = null;
$except  = null;
$time    = 0;

try {
    socket_select($sockets, $write, $except, $time);
} catch (ValueError $exception) {
    echo $exception->getMessage() . "\n";
}
});
?>
--EXPECTF--
socket_select(): At least one array argument must be passed
--CREDITS--
Till Klampaeckel, till@php.net
Berlin TestFest 2009
