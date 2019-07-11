--TEST--
swoole_coroutine/bailout: error out of the coroutine
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();

$func = function () {
    echo 'aaa' . PHP_EOL;
};

$socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
go(function () use ($socket, $func) {
    $socket->connect('192.0.0.1', 80);
    defer($func);
    defer('bbb');
    defer(function () use ($func) {
        echo 'ccc' . PHP_EOL;
        var_dump($func);
    });
});

function bbb()
{
    echo 'bbb' . PHP_EOL;
}

go(function () {
    $fp = stream_socket_client("tcp://127.0.0.1:3306", $errno, $errstr, 1);
    echo fread($fp, 8192) . PHP_EOL;
});

a();
?>
--EXPECTF--
Fatal error: Uncaught Error: Call to undefined function a() in %s:%d
Stack trace:
#0 {main}
  thrown in %s on line %d
