--TEST--
swoole_coroutine_channel: 10
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
    assert($chan->pop(0.001) == "data");
    assert($chan->pop(0.001) == false);
});

swoole_event::wait();
?>
--EXPECT--
