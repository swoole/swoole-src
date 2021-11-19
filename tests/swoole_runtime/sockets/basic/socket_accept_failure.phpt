--TEST--
socket_accept() failure
--FILE--
<?php
use Swoole\Runtime;
use function Swoole\Coroutine\run;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    var_dump(socket_accept($socket));
});
?>
--EXPECTF--
bool(false)
