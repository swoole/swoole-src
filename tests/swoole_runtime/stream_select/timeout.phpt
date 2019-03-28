--TEST--
swoole_runtime/stream_select: timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
go(function () {
    Swoole\Runtime::enableCoroutine();
    $fp1 = stream_socket_client("tcp://www.baidu.com:80", $errno, $errstr, 30);
    if (!$fp1) {
        echo "$errstr ($errno)<br />\n";
    } else {
        $r_array = [$fp1];
        $w_array = $e_array = null;
        $s = microtime(true);
        $n = stream_select($r_array, $w_array, $e_array, 1);
        Assert::eq($n, 0);
        assert(microtime(true) - $s > 0.99);
    }
});
?>
--EXPECT--
