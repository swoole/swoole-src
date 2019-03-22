--TEST--
swoole_channel_coro: pop priority
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Coroutine as co;

$chan = new co\Channel(2);

for ($i = 0; $i < 4; $i++) {
    go(function () use ($i, $chan) {
        $chan->push($i);
    });
};

swoole_timer_after(200, function () use ($chan) {
    for ($i = 0; $i < 6; $i++)  {
        $chan->push($i);
    }
});

go(function () use ($chan){
    for ($i = 0; $i < 2; $i++)  {
        echo "[read]".var_export($chan->pop(), 1)."\n";
    }
    for ($i = 0; $i < 8; $i++)  {
        echo "[read & write]".var_export($chan->pop(), 1)."\n";
    }
});

swoole_event::wait();
?>
--EXPECT--
[read]0
[read]1
[read & write]2
[read & write]3
[read & write]0
[read & write]1
[read & write]2
[read & write]3
[read & write]4
[read & write]5
