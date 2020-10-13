--TEST--
swoole_channel_coro: blocking and timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Co::set(['hook_flags' => 0]);

$chan = new chan();

go(function () use ($chan){
    $data = $chan->pop(0.5);
    Assert::assert($data);
    $data = $chan->pop(0.5);
    Assert::false($data);
});

go(function () use ($chan) {
    sleep(1);
    $chan->push(999955);
});

swoole_event::wait();
?>
--EXPECT--
