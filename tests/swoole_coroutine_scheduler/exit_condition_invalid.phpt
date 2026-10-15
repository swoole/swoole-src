--TEST--
swoole_coroutine_scheduler: invalid exit_condition preserves old callback
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$count = 0;
Swoole\Coroutine::set([
    'exit_condition' => function () use (&$count) {
        $count++;
        return true;
    },
]);

try {
    Swoole\Coroutine::set(['exit_condition' => 'not_found_function']);
    Assert::true(false, 'invalid exit_condition must throw');
} catch (Swoole\Exception $exception) {
    Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
    Assert::contains($exception->getMessage(), 'callback must be callable');
}
Swoole\Timer::after(1, function () {});
Swoole\Event::wait();

Assert::eq($count, 1);
echo "DONE\n";
?>
--EXPECT--
DONE
