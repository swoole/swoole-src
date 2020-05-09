--TEST--
swoole_server: duplicate registered
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$server = new Swoole\Server('127.0.0.1');
$server->on('start', function () { });
$mem = memory_get_usage();
for ($n = 1000; $n--;) {
    Assert::same(memory_get_usage(), $mem);
    $server->on('start', function () { });
}
echo "DONE\n";
?>
--EXPECT--
DONE
