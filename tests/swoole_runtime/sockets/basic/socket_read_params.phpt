--TEST--
swoole_runtime/sockets/basic: ext/sockets - socket_read- test with incorrect parameter
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
require __DIR__ . '/../../../include/bootstrap.php';

use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {
    $s_c_l = socket_create_listen(0);
    $s_c = socket_read($s_c_l, 25);
    Assert::false($s_c);
    socket_close($s_c_l);
});
?>
--EXPECTF--
