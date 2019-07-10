--TEST--
swoole_server: getCallback
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$server = new Swoole\Server('127.0.0.1');
$server->on('start', function ($server) { });
$server->on('shutdown', function ($server) { });
Assert::isInstanceOf($server->getCallback('start'), Closure::class);
Assert::assert(is_callable($server->getCallback('start')));
$cb = $server->getCallback('start');
Assert::same($cb, $server->getCallback('start'));
Assert::same($server->getCallback('Receive'), null);
$server->on('receive', function () { });
Assert::isInstanceOf($server->getCallback('receive'), Closure::class);
echo "DONE\n"
?>
--EXPECT--
DONE
