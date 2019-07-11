--TEST--
swoole_function: get local ip
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$ips = swoole_get_local_ip();
foreach ($ips as $ip) {
    Assert::same(filter_var($ip, FILTER_VALIDATE_IP), $ip);
    Assert::assert(strstr($ip, ".", true) !== "127");
}

?>
--EXPECT--
