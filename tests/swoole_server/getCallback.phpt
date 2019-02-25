--TEST--
swoole_server: getCallback
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$serv = new swoole_server('127.0.0.1', TCP_SERVER_PORT);

$serv->on("start", function ($server) {

});

$serv->on("shutdown", function ($server) {

});

assert($serv->getCallback("start") instanceof  Closure);
assert(is_callable($serv->getCallback("start")));

$cb = $serv->getCallback("start");
assert($cb === $serv->getCallback("start"));

assert($serv->getCallback("Receive") == null);
?>
--EXPECT--

