--TEST--
swoole_coroutine_scheduler: user yield and resume1
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

\Swoole\Coroutine\run(function () {
    echo 'scheduler 1: begin' . PHP_EOL;
    Swoole\Coroutine\System::sleep(0.1);
    echo 'scheduler 1: end' . PHP_EOL;
});

echo 'sleep: begin' . PHP_EOL;
usleep(100_000);
echo 'sleep: end' . PHP_EOL;

\Swoole\Coroutine\run(function () {
    echo 'scheduler 2: begin' . PHP_EOL;
    Swoole\Coroutine\System::sleep(0.1);
    echo 'scheduler 2: end' . PHP_EOL;
});

echo 'DONE' . PHP_EOL;

?>
--EXPECT--
scheduler 1: begin
scheduler 1: end
sleep: begin
sleep: end
scheduler 2: begin
scheduler 2: end
DONE
