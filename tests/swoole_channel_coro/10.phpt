--TEST--
swoole_channel_coro: 10
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $chan = new chan(3);
    go(function () use ($chan) {
        co::sleep(0.001);
        $chan->push("data");
    });
    Assert::same($chan->pop(0.001), "data");
    Assert::false($chan->pop(0.001));
});

swoole_event::wait();
?>
--EXPECT--
