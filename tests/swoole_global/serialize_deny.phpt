--TEST--
swoole_global: deny serialize and unserialize
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
go(function () {
    try {
        $hcc = new \Swoole\Atomic();
        serialize($hcc);
        assert(false);
    } catch (\Exception $exception) {
        assert(strpos($exception->getMessage(), 'Serialization') === 0);
    }
    try {
        $hcc = new \Swoole\Buffer();
        serialize($hcc);
        assert(false);
    } catch (\Exception $exception) {
        assert(strpos($exception->getMessage(), 'Serialization') === 0);
    }
    try {
        $hcc = new \Swoole\Client(SWOOLE_TCP);
        serialize($hcc);
        assert(false);
    } catch (\Exception $exception) {
        assert(strpos($exception->getMessage(), 'Serialization') === 0);
    }
    try {
        $hcc = new \Swoole\Coroutine\Client(SWOOLE_TCP);
        serialize($hcc);
        assert(false);
    } catch (\Exception $exception) {
        assert(strpos($exception->getMessage(), 'Serialization') === 0);
    }
    try {
        $hcc = new \Swoole\Coroutine\Http\Client('127.0.0.1');
        serialize($hcc);
        assert(false);
    } catch (\Exception $exception) {
        assert(strpos($exception->getMessage(), 'Serialization') === 0);
    }
    try {
        $hcc = new \Swoole\Coroutine\Mysql();
        serialize($hcc);
        assert(false);
    } catch (\Exception $exception) {
        assert(strpos($exception->getMessage(), 'Serialization') === 0);
    }
    try {
        $hcc = new \Swoole\Coroutine\Redis();
        serialize($hcc);
        assert(false);
    } catch (\Exception $exception) {
        assert(strpos($exception->getMessage(), 'Serialization') === 0);
    }
    try {
        $hcc = new \Swoole\Table(1);
        serialize($hcc);
        assert(false);
    } catch (\Exception $exception) {
        assert(strpos($exception->getMessage(), 'Serialization') === 0);
    }
});
?>
--EXPECT--