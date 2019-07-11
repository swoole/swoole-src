--TEST--
swoole_channel_coro: coro channel
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Coroutine as co;
$chan = new co\Channel(1);
co::create(function () use ($chan) {
    for($i=1; $i<=10; $i++) {
        co::sleep(0.01);
        $chan->push($i);
        echo "$i\n";
    }
});

co::create(function () use ($chan) {
    for($i=0; $i<10; $i++) {
        $data = $chan->pop();
        Assert::assert(!empty($data));
    }
});

swoole_event::wait();

?>
--EXPECT--
1
2
3
4
5
6
7
8
9
10
