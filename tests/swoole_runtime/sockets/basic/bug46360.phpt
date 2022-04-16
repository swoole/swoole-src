--TEST--
swoole_runtime/sockets/basic: Bug 46360 - TCP_NODELAY constant (sock_get_option, sock_set_option)
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
<?php if (!extension_loaded('sockets')) die('skip sockets extension not loaded'); ?>
--CREDITS--
Florian Anderiasch
fa@php.net
--FILE--
<?php
use Swoole\Runtime;
use function Swoole\Coroutine\run;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {

    var_dump(TCP_NODELAY);
});
?>
--EXPECTF--
int(%d)
