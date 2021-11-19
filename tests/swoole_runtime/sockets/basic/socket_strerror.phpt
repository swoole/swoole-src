--TEST--
ext/sockets - socket_strerror - basic test
--CREDITS--
Florian Anderiasch
fa@php.net
--SKIPIF--
<?php
if (!extension_loaded('sockets')) {
    die('skip sockets extension not available.');
}
if (!stristr(PHP_OS, "Linux")) {
    die('skip - test validates linux error strings only.');
}
?>
--FILE--
<?php
use Swoole\Runtime;
use function Swoole\Coroutine\run;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {

/* Only test one representative error code here,
 * as messages will differ depending on the used libc. */
var_dump(socket_strerror(1));
});
?>
--EXPECT--
string(23) "Operation not permitted"
