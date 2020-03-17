--TEST--
swoole_runtime: sleep
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$host = 'www.tsinghua.edu.cn';
$ip1 = gethostbyname($host);
Swoole\Runtime::enableCoroutine();
go(function () use($ip1, $host) {
    $ip2 = gethostbyname($host);
    Assert::same($ip1, $ip2);
});
?>
--EXPECTF--
