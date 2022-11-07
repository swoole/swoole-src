--TEST--
swoole_coroutine/defer: coro defer with exception
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
go(function () {
    go(function () {
        $foo = 1;
        $bar = 'cha';
        defer(function () use ($foo, $bar) {
            echo "defer 1\n";
            Assert::same($foo, 1);
            Assert::same($bar, 'cha');
        });
        $foo = 2;
        $bar = 'gua';
        defer(function () use ($foo, &$bar) {
            echo "defer 2\n";
            Assert::same($foo, 2);
            Assert::assert($bar !== 'gua'); // because of &
        });
        $foo = 3;
        $bar = 'zha';
        echo $foo, "\n", $bar, "\n";
        throw new Exception('something wrong');
        echo "never here\n";
    });
});
Swoole\Event::wait();
?>
--EXPECTF--
3
zha

Fatal error: Uncaught Exception: something wrong in %s:%d
Stack trace:
%A
  thrown in %s/tests/swoole_coroutine/defer/defer_exception.php on line %d
defer 2
defer 1
