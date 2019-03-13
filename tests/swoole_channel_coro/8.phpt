--TEST--
swoole_channel_coro: pop priority
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Coroutine as co;

$chan = new co\Channel(2);
$n = 4;

for ($i = 0; $i < $n; $i++) {
    go(function () use ($i, $chan) {
        echo "[pop]".var_export($chan->pop(), 1)."\n";
    });
};

swoole_timer_after(500, function () use ($chan) {
    for ($i = 0; $i < 6; $i++)  {
        $chan->push($i);
    }
});

go(function ()use ($chan){
    for ($i = 0; $i < 4; $i++)  {
        $chan->push($i);
    }
    for ($i = 0; $i < 6; $i++)  {
        echo "[pop & push]".var_export($chan->pop($i), 1)."\n";
    }
});

swoole_event::wait();
?>
--EXPECT--
[pop]0
[pop]1
[pop]2
[pop]3
[pop & push]0
[pop & push]1
[pop & push]2
[pop & push]3
[pop & push]4
[pop & push]5
