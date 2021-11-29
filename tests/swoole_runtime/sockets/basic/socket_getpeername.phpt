--TEST--
swoole_runtime/sockets/basic: ext/sockets - socket_getpeername - basic test
--CREDITS--
Florian Anderiasch
fa@php.net
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
<?php
    if (!extension_loaded('sockets')) {
        die('skip sockets extension not available.');
    }
?>
--FILE--
<?php
use Swoole\Runtime;
use function Swoole\Coroutine\run;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {

    $s_c     = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    $s_bind  = socket_bind($s_c, '0.0.0.0');
    var_dump($s_bind);

    // Connect to destination address
    $s_peer  = socket_getpeername($s_c, $ip, $port);
    var_dump($s_peer);
    var_dump($ip);
    var_dump($port);
    socket_close($s_c);
});
?>
--EXPECTF--
bool(true)
bool(false)
NULL
NULL
