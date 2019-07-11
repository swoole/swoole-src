--TEST--
swoole_global: deny create object
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    try {
        new Swoole\Coroutine;
    } catch (Error $e) {
        echo $e->getMessage() . PHP_EOL;
    }
    try {
        new Swoole\Event;
    } catch (Error $e) {
        echo $e->getMessage() . PHP_EOL;
    }
    try {
        new Swoole\Runtime;
    } catch (Error $e) {
        echo $e->getMessage() . PHP_EOL;
    }
    try {
        new Swoole\Timer;
    } catch (Error $e) {
        echo $e->getMessage() . PHP_EOL;
    }
});
?>
--EXPECT--
The object of Swoole\Coroutine can not be created for security reasons
The object of Swoole\Event can not be created for security reasons
The object of Swoole\Runtime can not be created for security reasons
The object of Swoole\Timer can not be created for security reasons
