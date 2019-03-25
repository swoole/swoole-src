--TEST--
swoole_server: getCallback
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$serv = new Swoole\Server('127.0.0.1');
$serv->on("start", function ($server) { });
$serv->on("shutdown", function ($server) { });
Assert::isInstanceOf($serv->getCallback("start"), Closure::class);
assert(is_callable($serv->getCallback("start")));
$cb = $serv->getCallback("start");
Assert::eq($cb, $serv->getCallback("start"));
Assert::eq($serv->getCallback("Receive"), null);
echo "DONE\n"
?>
--EXPECT--
DONE
