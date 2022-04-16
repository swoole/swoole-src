--TEST--
swoole_runtime/sockets/basic: Test parameter handling in socket_listen().
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
<?php
if (substr(PHP_OS, 0, 3) == 'WIN') {
    die('skip.. Not valid for Windows');
}
if (!extension_loaded('sockets')) {
    die('SKIP The sockets extension is not loaded.');
} ?>
--FILE--
<?php
require __DIR__ . '/../../../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {
    $socket = socket_create(AF_UNIX, SOCK_STREAM, 0);
    var_dump(socket_listen($socket));
});
?>
--EXPECTF--
bool(false)
--CREDITS--
Till Klampaeckel, till@php.net
Berlin TestFest 2009
