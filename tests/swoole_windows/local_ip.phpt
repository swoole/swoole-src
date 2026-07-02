--TEST--
swoole_windows: get local ip
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (stripos(PHP_OS, 'WIN') !== 0) {
    die('skip Windows only');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$ips = swoole_get_local_ip();
Assert::assert(is_array($ips));
Assert::assert(!empty($ips));
Assert::same('127.0.0.1', $ips[0]);

foreach ($ips as $ip) {
    Assert::same(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4), $ip);
}

echo "DONE\n";
?>
--EXPECT--
DONE
