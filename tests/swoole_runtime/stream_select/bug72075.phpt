--TEST--
swoole_runtime/stream_select: Bug #72075 (Referencing socket resources breaks stream_select)
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
go(function () {
    $r = [stream_socket_server("tcp://127.0.0.1:0", $errno, $errStr)];
    $w = null;
    $e = null;

    // Without this line, all is well:
    $dummy =& $r[0];

    print stream_select($r, $w, $e, 0.5) . PHP_EOL;
});
Swoole\Event::wait();
?>
--EXPECT--
0
