--TEST--
swoole_coroutine_scheduler: retain unstarted tasks when coroutine creation fails
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$scheduler = new Swoole\Coroutine\Scheduler;
$scheduler->set(['max_coroutine' => 1]);
foreach ([0, -1] as $count) {
    try {
        $scheduler->parallel($count, static function () {});
        Assert::true(false, 'parallel must reject non-positive counts');
    } catch (ValueError $exception) {
        Assert::contains($exception->getMessage(), 'must be greater than 0');
    }
}
$log = [];
$scheduler->parallel(3, static function ($label) use (&$log) {
    $log[] = $label . ':begin';
    Swoole\Coroutine::sleep(0.001);
    $log[] = $label . ':end';
}, 'parallel');
$scheduler->add(static function () use (&$log) { $log[] = 'tail'; });
for ($i = 1; $i <= 3; $i++) {
    Assert::false(@$scheduler->start());
    Assert::same(count($log), $i * 2);
    Assert::same(Swoole\Coroutine::stats()['coroutine_num'], 0);
}
Assert::true($scheduler->start());
Assert::same($log, [
    'parallel:begin', 'parallel:end',
    'parallel:begin', 'parallel:end',
    'parallel:begin', 'parallel:end',
    'tail',
]);

// A PHP exception from the creation warning must also reset the running state and keep the queue.
$scheduler->parallel(2, static function () use (&$log) {
    Swoole\Coroutine::sleep(0.001);
    $log[] = 'exception-retry';
});
set_error_handler(static function ($severity, $message) {
    throw new ErrorException($message, 0, $severity);
});
try {
    $scheduler->start();
    Assert::true(false, 'creation warning must propagate the exception');
} catch (ErrorException $exception) {
    Assert::contains($exception->getMessage(), 'exceed max number');
} finally {
    restore_error_handler();
}
$scheduler->set(['max_coroutine' => 2]);
Assert::true($scheduler->start());
Assert::same(array_slice($log, 7), ['exception-retry', 'exception-retry']);
echo "DONE\n";
?>
--EXPECT--
DONE
