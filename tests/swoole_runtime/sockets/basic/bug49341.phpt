--TEST--
Bug #49341: add SO_REUSEPORT support for socket_set_option()
--SKIPIF--
<?php
if (!extension_loaded('sockets')) {
    die('skip sockets extension not available.');
}
if (PHP_OS !== 'Darwin' && false === strpos(PHP_OS, 'BSD')) {
    die('skip is not *BSD.');
}
?>
<?phpuse function Swoole\Coroutine\run;
use Swoole\Runtime;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {
use function Swoole\Coroutine\run;
use Swoole\Runtime;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {
    var_dump(defined('SO_REUSEPORT'));
});
?>
--EXPECT--
bool(true)
