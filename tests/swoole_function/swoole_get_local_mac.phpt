--TEST--
swoole_function: get mac address
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$macs = swoole_get_local_mac();
Assert::assert(is_array($macs));
foreach ($macs as $mac) {
    Assert::same(filter_var($mac, FILTER_VALIDATE_MAC), $mac);
}

?>
--EXPECT--
