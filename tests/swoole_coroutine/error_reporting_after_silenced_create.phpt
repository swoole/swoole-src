--TEST--
swoole_coroutine: isolate error reporting from silenced create
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$expected = error_reporting();
$levels = [];

@Swoole\Coroutine\run(function () use ($expected, &$levels) {
    $cid = @Swoole\Coroutine::create(function () use (&$levels) {
        $levels[] = error_reporting();
        Swoole\Coroutine::yield();
        $levels[] = error_reporting();
    });

    Assert::same(error_reporting(), $expected);
    Swoole\Coroutine::resume($cid);
});

Assert::same(error_reporting(), $expected);
Assert::same($levels, [$expected, $expected]);
echo "DONE\n";
?>
--EXPECT--
DONE
