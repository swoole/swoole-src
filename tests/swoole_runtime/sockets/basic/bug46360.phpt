--TEST--
Bug 46360 - TCP_NODELAY constant (sock_get_option, sock_set_option)
--SKIPIF--
<?php if (!extension_loaded('sockets')) {
    die('skip sockets extension not loaded');
} ?>
--CREDITS--
Florian Anderiasch
fa@php.net
--FILE--
<?php

use function Swoole\Coroutine\run;

run(function () {
    var_dump(TCP_NODELAY);
});
?>
--EXPECTF--
int(%d)
