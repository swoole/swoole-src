--TEST--
swoole_runtime/sockets/basic: void socket_clear_error ([ resource $socket ] ) ;
--CREDITS--
marcosptf - <marcosptf@yahoo.com.br> - #phparty7 - @phpsp - novatec/2015 - sao paulo - br
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
<?php
if (!extension_loaded('sockets')) {
  die('SKIP sockets extension not available.');
}
if(substr(PHP_OS, 0, 3) == 'WIN' ) {
    die('skip windows only test');
}
?>
--FILE--
<?php
use Swoole\Runtime;
use function Swoole\Coroutine\run;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {

    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    $socketConn = socket_connect($socket, "127.0.0.1", 21248);
    var_dump(socket_last_error($socket));
    socket_clear_error($socket);
    var_dump(socket_last_error($socket));

    socket_close($socket);
    unset($socket);
    unset($socketConn);
});
?>
--EXPECTF--
int(%d)
int(%d)
