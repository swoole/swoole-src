--TEST--
swoole_runtime/sockets/basic: ext/sockets - socket_connect - test with empty parameters
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
    $s_c = socket_create_listen(0);
    socket_getsockname($s_c, $addr, $port);

    // wrong parameter count
    try {
        Assert::false(socket_connect($s_c));
    } catch (\ArgumentCountError $e) {
        echo $e->getMessage() . \PHP_EOL;
    }
    try {
        Assert::false(socket_connect($s_c, '0.0.0.0'));
    } catch (\ValueError $e) {
        echo $e->getMessage() . \PHP_EOL;
    }
    $s_w = socket_connect($s_c, '0.0.0.0', $port);

    socket_close($s_c);
});
?>
--EXPECTF--
Too few arguments to function swoole_socket_connect(), 1 passed and at least 2 expected

Warning: Swoole\Coroutine\Socket::connect(): Invalid port argument[0] in %s on line %d
