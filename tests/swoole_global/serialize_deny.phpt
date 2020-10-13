--TEST--
swoole_global: deny serialize and unserialize
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    try {
        $hcc = new \Swoole\Atomic();
        serialize($hcc);
        Assert::true(false, 'never here');
    } catch (\Exception $exception) {
        Assert::same(strpos($exception->getMessage(), 'Serialization'), 0);
    }
    try {
        $hcc = new \Swoole\Client(SWOOLE_TCP);
        serialize($hcc);
        Assert::true(false, 'never here');
    } catch (\Exception $exception) {
        Assert::same(strpos($exception->getMessage(), 'Serialization'), 0);
    }
    try {
        $hcc = new \Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        serialize($hcc);
        Assert::true(false, 'never here');
    } catch (\Exception $exception) {
        Assert::same(strpos($exception->getMessage(), 'Serialization'), 0);
    }
    try {
        $hcc = new \Swoole\Coroutine\Http\Client('127.0.0.1');
        serialize($hcc);
        Assert::true(false, 'never here');
    } catch (\Exception $exception) {
        Assert::same(strpos($exception->getMessage(), 'Serialization'), 0);
    }
    try {
        $hcc = new \Swoole\Coroutine\Mysql();
        serialize($hcc);
        Assert::true(false, 'never here');
    } catch (\Exception $exception) {
        Assert::same(strpos($exception->getMessage(), 'Serialization'), 0);
    }
    if (HAS_ASYNC_REDIS) {
        try {
            $hcc = new \Swoole\Coroutine\Redis();
            serialize($hcc);
            Assert::true(false, 'never here');
        } catch (\Exception $exception) {
            Assert::same(strpos($exception->getMessage(), 'Serialization'), 0);
        }
    }
    try {
        $hcc = new \Swoole\Table(1);
        serialize($hcc);
        Assert::true(false, 'never here');
    } catch (\Exception $exception) {
        Assert::same(strpos($exception->getMessage(), 'Serialization'), 0);
    }
});
?>
--EXPECT--
