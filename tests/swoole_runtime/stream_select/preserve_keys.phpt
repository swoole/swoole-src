--TEST--
swoole_runtime/stream_select: Bug #53427 + emulate_read (stream_select does not preserve keys)
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
go(function () {
    $read[1] = fopen(__FILE__, 'r');
    $read['myindex'] = fopen(__FILE__, 'r');
    $write = null;
    $except = null;

    Assert::count($read, 2);
    $n = stream_select($read, $write, $except, 0);
    Assert::same($n, 2);
    Assert::count($read, 2);
    Assert::isEmpty($write);
    Assert::isEmpty($except);
    fread(reset($read), 1);
    $n = stream_select($read, $write, $except, 0); // // emulate_read
    Assert::same($n, 1);
    Assert::count($read, 1);
    Assert::isEmpty($write);
    Assert::isEmpty($except);
});
Swoole\Event::wait();
echo "DONE\n"
?>
--EXPECTF--
DONE
