--TEST--
swoole_runtime/stream_select: blocked
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
Swoole\Runtime::enableCoroutine(false);
$fp1 = stream_socket_client("tcp://www.baidu.com:80", $errno, $errstr, 30);
$fp2 = stream_socket_client("tcp://www.qq.com:80", $errno, $errstr, 30);
if (!$fp1) {
    echo "$errstr ($errno)<br />\n";
} else {
    fwrite($fp1, "GET / HTTP/1.0\r\nHost: www.baidu.com\r\nUser-Agent: curl/7.58.0\r\nAccept: */*\r\n\r\n");
    $r_array = [$fp1, $fp2];
    $w_array = $e_array = null;
    $n = stream_select($r_array, $w_array, $e_array, 10);
    Assert::assert($n == 1);
    Assert::assert(count($r_array) == 1);
    Assert::assert($r_array[0] == $fp1);
    $html = '';
    while (!feof($fp1)) {
        $html .= fgets($fp1, 1024);
    }
    Assert::assert(strlen($html) > 1024);
    fclose($fp1);
}
echo "DONE\n";
?>
--EXPECT--
DONE
