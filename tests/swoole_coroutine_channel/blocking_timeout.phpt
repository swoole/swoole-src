--TEST--
swoole_coroutine_channel: blocking and timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$chan = new chan();
go(function () use ($chan)
{
    $data = $chan->pop(0.5);
    assert($data);
    $data = $chan->pop(0.5);
    assert($data == false);
});

go(function () use ($chan)
{
    sleep(1);
    $chan->push(999955);
});

swoole_event::wait();
?>
--EXPECT--
