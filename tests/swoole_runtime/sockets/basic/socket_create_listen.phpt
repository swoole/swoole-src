--TEST--
swoole_runtime/sockets/basic: Test if socket binds on 31338
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
<?php
if (substr(PHP_OS, 0, 3) == 'WIN') {
    die('skip.. Not valid for Windows');
}
if (!extension_loaded('sockets')) {
    die('SKIP The sockets extension is not loaded.');
}?>
--FILE--
<?php
use Swoole\Runtime;
use function Swoole\Coroutine\run;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {

$sock = socket_create_listen(31338);
socket_getsockname($sock, $addr, $port);
var_dump($addr, $port);
});
?>
--EXPECT--
string(7) "0.0.0.0"
int(31338)
--CREDITS--
Till Klampaeckel, till@php.net
PHP Testfest Berlin 2009-05-09
