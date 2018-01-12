--TEST--
swoole_coroutine: sleep
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

use Swoole\Coroutine as co;

co::create(function () {
    co::sleep(0.5);
    echo "OK";
});

?>
--EXPECT--
OK