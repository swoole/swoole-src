--TEST--
swoole_function: get local ip
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$ips = swoole_get_local_ip();
Assert::isArray($ips);
Assert::notEmpty($ips);

foreach ($ips as $name => $ip) {
    Assert::stringNotEmpty($name);
    Assert::same(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4), $ip);
    Assert::false(str_starts_with($ip, '127.'));
}

echo "DONE\n";
?>
--EXPECT--
DONE
