--TEST--
swoole_runtime/sockets/basic: add SO_REUSEPORT support for socket_set_option()
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
<?php
if (!extension_loaded('sockets')) {
    die('skip sockets extension not available.');
}
if (PHP_OS !== 'Darwin' && false === strpos(PHP_OS, 'BSD')) {
    die('skip is not *BSD.');
}?>
--FILE--
<?php
use Swoole\Runtime;
use function Swoole\Coroutine\run;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {

var_dump(defined('SO_REUSEPORT'));
});
?>
--EXPECT--
bool(true)
