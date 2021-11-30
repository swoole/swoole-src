--TEST--
swoole_runtime/sockets/basic: Test if socket_set_option() returns 'Unable to set socket option' failure for invalid options
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
<?php
if (!extension_loaded('sockets')) {
    die('SKIP sockets extension not available.');
}
if (PHP_OS == 'Darwin') {
    die('skip Not for OSX');
}
$filename = __FILE__ . '.root_check.tmp';
$fp = fopen($filename, 'w');
fclose($fp);
if (fileowner($filename) == 0) {
    unlink($filename);
    die('SKIP Test cannot be run as root.');
}
unlink($filename);
?>
--FILE--
<?php

use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if (!$socket) {
        die('Unable to create AF_INET socket [socket]');
    }

    socket_set_option($socket, SOL_SOCKET, 1, 1);
    socket_close($socket);
});
?>
--EXPECTF--
Warning: Swoole\Coroutine\Socket::setOption(): setsockopt(4) failed, Error: Permission denied[13] in %s on line %d
--CREDITS--
Moritz Neuhaeuser, info@xcompile.net
PHP Testfest Berlin 2009-05-10
