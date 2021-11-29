--TEST--
swoole_runtime/sockets/basic: Test socket_set_nonblock return values
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
<?php
if (!extension_loaded('sockets')) {
    die('SKIP The sockets extension is not loaded.');
}
?>
--FILE--
<?php

use Swoole\Runtime;

use function Swoole\Coroutine\run;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {
    $socket = socket_create_listen(31339);
    var_dump(socket_set_nonblock($socket));
    socket_close($socket);

    $socket2 = socket_create_listen(31340);
    socket_close($socket2);
    try {
        var_dump(socket_set_nonblock($socket2));
    } catch (Error $e) {
        echo $e->getMessage(), "\n";
    }
});
?>
--EXPECT--
bool(true)
bool(false)
