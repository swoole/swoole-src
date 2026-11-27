--TEST--
swoole_client_async: on() requires the full event name
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
error_reporting(E_ALL & ~E_DEPRECATED);

$cli = new Swoole\Async\Client(SWOOLE_SOCK_TCP);
foreach (['', 'c', 'conn', 'r', 'e', 'connectx', 'foo'] as $name) {
    Assert::false(@$cli->on($name, function () {}), "'$name'");
}
foreach (['connect', 'RECEIVE', 'Close', 'error', 'bufferFull', 'bufferEmpty'] as $name) {
    Assert::true($cli->on($name, function () {}), $name);
}
echo "DONE\n";
?>
--EXPECT--
DONE
