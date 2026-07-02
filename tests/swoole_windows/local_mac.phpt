--TEST--
swoole_windows: get local mac
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

$macs = swoole_get_local_mac();
Assert::assert(is_array($macs));
Assert::assert(!empty($macs));

foreach ($macs as $mac) {
    Assert::same(filter_var($mac, FILTER_VALIDATE_MAC), $mac);
}

echo "DONE\n";
?>
--EXPECT--
DONE
