--TEST--
swoole_timer: after fork
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$id = Swoole\Timer::after(1, function () { echo 'never here' . PHP_EOL; });
if (Assert::greaterThan($id, 0)) {
    $process = new Swoole\Process(function () use ($id) {
        // timer will be removed before fork
        Assert::false(Swoole\Timer::exists($id));
        echo "DONE\n";
    });
    $process->start();
    $process::wait();
    Assert::true(Swoole\Timer::clear($id));
}
Swoole\Event::wait();
?>
--EXPECT--
DONE
