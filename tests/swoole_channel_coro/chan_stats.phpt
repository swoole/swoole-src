--TEST--
swoole_channel_coro: coro channel stats
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$chan = new chan(10);

go(function () use ($chan) {
    $chan->push(1);
    $chan->push(2);
    $chan->push("hello world");
    $chan->push([1, 3, 4, 4, 6]);
    Assert::same($chan->stats()['queue_num'], 4);

    $chan->pop();
    $chan->pop();
    $chan->pop();
    $chan->pop();
    Assert::same($chan->stats()['queue_num'], 0);
});

swoole_event::wait();
?>
--EXPECT--
