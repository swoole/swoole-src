--TEST--
swoole_runtime: base
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Swoole\Runtime::enableCoroutine(true, SWOOLE_HOOK_ALL ^ SWOOLE_HOOK_SLEEP);
go(function () {
    usleep(1000);
    echo '1' . PHP_EOL;
});
echo '2' . PHP_EOL;
go(function () {
    $read = [fopen(__FILE__, 'r')];
    $n = stream_select($read, $write, $except, 1);
    Assert::eq(1, $n);
    Assert::count($read, 1);
    echo 'select' . PHP_EOL;
});
echo '3' . PHP_EOL;
Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_ALL ^ SWOOLE_HOOK_FILE ^ SWOOLE_HOOK_STREAM_SELECT);
go(function () {
    $read = [fopen(__FILE__, 'r')];
    $n = stream_select($read, $write, $except, 1);
    Assert::eq(1, $n);
    Assert::count($read, 1);
    echo '4' . PHP_EOL;
});
go(function () {
    usleep(10 * 1000);
    echo 'sleep2' . PHP_EOL;
});
echo '5' . PHP_EOL;
Swoole\Runtime::enableCoroutine(true); // all
go(function () {
    usleep(5 * 1000);
    echo 'sleep1' . PHP_EOL;
});
echo '6' . PHP_EOL;
go(function () {
    $read = [fopen(__FILE__, 'r')];
    $n = stream_select($read, $write, $except, 1);
    Assert::eq(1, $n);
    Assert::count($read, 1);
    echo 'select' . PHP_EOL;
});
echo '7' . PHP_EOL;
Swoole\Event::wait();
Swoole\Runtime::enableCoroutine(false); // disable all
?>
--EXPECT--
1
2
3
4
5
6
7
8
