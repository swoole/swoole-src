--TEST--
swoole_coroutine_channel: zero_buffer
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$chan = new \Swoole\Coroutine\Channel(0);

go(function () use ($chan) {
    co::sleep(0.5);
    assert($chan->pop() == 'swoole');
    assert($chan->pop(0.1) == 'false');
});

go(function () use ($chan) {
    assert($chan->push(1, 0.1) == 'false');
    assert($chan->push('swoole') == 'true');
});

swoole_event::wait();
?>
--EXPECT--
