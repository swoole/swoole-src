--TEST--
swoole_channel_coro: push and pop
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Coroutine as co;

$chan = new co\Channel(2);
$n = 10;
for ($i = 0; $i < $n; $i++) {
    go(function () use ($i,$chan) {
        $chan->push($i);
    });
};

go(function ()use ($chan){
    $bool = true;
    for ($i = 0; $i < 10; $i++)  {
        $data = $chan->pop();
        if ($data===false) {
            $bool = false;
        }
        var_dump($data);
    }
});

swoole_event::wait();
?>
--EXPECT--
int(0)
int(1)
int(2)
int(3)
int(4)
int(5)
int(6)
int(7)
int(8)
int(9)
