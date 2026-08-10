--TEST--
swoole_function: get mac address
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$macs = swoole_get_local_mac();
Assert::isArray($macs);
Assert::notEmpty($macs);

foreach ($macs as $name => $mac) {
    Assert::stringNotEmpty($name);
    Assert::same(filter_var($mac, FILTER_VALIDATE_MAC), $mac);
}

echo "DONE\n";
?>
--EXPECT--
DONE
