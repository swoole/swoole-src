--TEST--
swoole_runtime: sleep
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$host = "www.swoole.com";
$ip1 = gethostbyname($host);
Swoole\Runtime::enableCoroutine();
go(function () use($ip1, $host) {
    $ip2 = gethostbyname($host);
    Assert::eq($ip1, $ip2);
});
?>
--EXPECTF--
