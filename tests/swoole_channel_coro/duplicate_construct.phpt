--TEST--
swoole_channel_coro: duplicate construct
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = ProcessManager::exec(function () {
    $chan = new Swoole\Coroutine\Channel(1);
    $chan->__construct(2);
});

Assert::contains($pm->getChildOutput(), "channel has already been constructed");
?>
--EXPECT--
