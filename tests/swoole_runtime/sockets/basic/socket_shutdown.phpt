--TEST--
swoole_runtime/sockets/basic: bool socket_shutdown ( resource $socket [, int $how = 2 ] ) ;
--CREDITS--
marcosptf - <marcosptf@yahoo.com.br> - #phparty7 - @phpsp - novatec/2015 - sao paulo - br
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
<?php
if (getenv("SKIP_ONLINE_TESTS")) die("skip online test");
if (!extension_loaded('sockets')) {
  die('SKIP sockets extension not available.');
}
if(substr(PHP_OS, 0, 3) == 'WIN' ) {
    die('skip not for windows');
}
?>
--FILE--
<?php
use Swoole\Runtime;
use function Swoole\Coroutine\run;

Runtime::setHookFlags(SWOOLE_HOOK_SOCKETS);

run(function () {
    $host = "yahoo.com";
    $port = 80;

    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    $socketConn = socket_connect($socket, $host, $port);
    var_dump(socket_shutdown($socket, 0));
    socket_close($socket);

    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    $socketConn = socket_connect($socket, $host, $port);
    var_dump(socket_shutdown($socket, 1));
    socket_close($socket);

    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    $socketConn = socket_connect($socket, $host, $port);
    var_dump(socket_shutdown($socket, 2));
    socket_close($socket);

    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    var_dump(socket_shutdown($socket, 0));

    $socketConn = socket_connect($socket, $host, $port);
    var_dump(socket_shutdown($socket, -1));
    socket_close($socket);
});
?>
--CLEAN--
<?php
unset($host);
unset($port);
unset($socket);
unset($socketConn);
?>
--EXPECTF--
bool(true)
bool(true)
bool(true)
bool(false)
bool(false)
