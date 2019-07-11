--TEST--
swoole_runtime/stream_select: timeout
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
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
        $timeout = ms_random(0.1, 0.5);
        $n = stream_select($r_array, $w_array, $e_array, 0, $timeout * 1000000);
        Assert::same($n, 0);
        time_approximate($timeout, microtime(true) - $s);
        echo "SUCCESS\n";
    }
});
?>
--EXPECT--
SUCCESS
