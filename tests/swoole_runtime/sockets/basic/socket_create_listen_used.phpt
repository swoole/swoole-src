--TEST--
swoole_runtime/sockets/basic: ext/sockets - socket_create_listen - test for used socket
--CREDITS--
Florian Anderiasch
fa@php.net
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
<?php
    if (!extension_loaded('sockets')) {
        die('skip - sockets extension not available.');
    }
?>
--FILE--
<?php
require __DIR__ . '/../../../include/bootstrap.php';
use Swoole\Runtime;
use function Swoole\Coroutine\run;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {

    $rand = rand(1,999);
    // wrong parameter count
    $s_c_l = socket_create_listen(31330+$rand);
    Assert::isInstanceOf($s_c_l, Swoole\Coroutine\Socket::class);
    // default invocation
    $s_c_l2 = socket_create_listen(31330+$rand);
    Assert::false($s_c_l2);
    socket_close($s_c_l);
});
?>
--EXPECT--
