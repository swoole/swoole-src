--TEST--
swoole_coroutine: user coroutine
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
Swoole\Coroutine::create(function ()
{
    echo "OK\n";
});

?>
--EXPECT--
OK