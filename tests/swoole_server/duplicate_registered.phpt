--TEST--
swoole_server: duplicate registered
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$server = new Swoole\Server('127.0.0.1');
$server->on('start', function () { });
Assert::same(true, !!'load Assert');
$mem = null;
for ($n = 1000; $n--;) {
    $server->on('start', function () { });
    if ($mem === null) {
        $mem = memory_get_usage();
    }
    Assert::same(memory_get_usage(), $mem);
}
echo "DONE\n";
?>
--EXPECT--
DONE
