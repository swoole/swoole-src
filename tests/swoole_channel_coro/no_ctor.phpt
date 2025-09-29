--TEST--
swoole_channel_coro: no ctor
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

class MyChan extends Swoole\Coroutine\Channel
{
    function __construct($size = null)
    {

    }
}

$pm = ProcessManager::exec(function () {
    go(function () {
        $chan = new MyChan(100);
        $chan->pop();
    });
});

Assert::contains($pm->getChildOutput(), "must call constructor first");
?>
--EXPECT--
